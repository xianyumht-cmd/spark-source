#!/usr/bin/env python3
"""Dependency-free static PE analyzer for the protected 32-bit sample.

The script does not execute the target. It extracts headers, sections, imports,
resources, version strings, and the XOR-0x11 encoded dynamic import inventory.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import math
import re
import struct
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

RESOURCE_TYPES = {
    1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG",
    6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR",
    10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR",
    14: "GROUP_ICON", 16: "VERSION", 24: "MANIFEST",
}


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def sha(path: Path, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


class PE:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        if self.data[:2] != b"MZ":
            raise ValueError("not an MZ executable")
        self.pe_offset = u32(self.data, 0x3C)
        if self.data[self.pe_offset:self.pe_offset + 4] != b"PE\0\0":
            raise ValueError("missing PE signature")
        self.coff = self.pe_offset + 4
        self.machine = u16(self.data, self.coff)
        self.section_count = u16(self.data, self.coff + 2)
        self.timestamp = u32(self.data, self.coff + 4)
        self.optional_size = u16(self.data, self.coff + 16)
        self.characteristics = u16(self.data, self.coff + 18)
        self.optional = self.coff + 20
        self.magic = u16(self.data, self.optional)
        if self.magic != 0x10B:
            raise ValueError(f"only PE32 is supported, magic={self.magic:#x}")
        self.entry_rva = u32(self.data, self.optional + 16)
        self.image_base = u32(self.data, self.optional + 28)
        self.section_alignment = u32(self.data, self.optional + 32)
        self.file_alignment = u32(self.data, self.optional + 36)
        self.size_of_image = u32(self.data, self.optional + 56)
        self.size_of_headers = u32(self.data, self.optional + 60)
        self.subsystem = u16(self.data, self.optional + 68)
        self.directory_offset = self.optional + 96
        self.sections: list[dict[str, Any]] = []
        sec_base = self.optional + self.optional_size
        for index in range(self.section_count):
            off = sec_base + index * 40
            name = self.data[off:off + 8].rstrip(b"\0").decode("latin1", "replace")
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", self.data, off + 8)
            characteristics = u32(self.data, off + 36)
            raw = self.data[raw_offset:raw_offset + raw_size] if raw_offset and raw_size else b""
            self.sections.append({
                "index": index,
                "name": name,
                "virtual_address": virtual_address,
                "virtual_size": virtual_size,
                "raw_offset": raw_offset,
                "raw_size": raw_size,
                "characteristics": characteristics,
                "entropy": round(entropy(raw), 6),
                "nonzero_ratio": round(sum(byte != 0 for byte in raw) / len(raw), 6) if raw else 0.0,
            })

    def directory(self, index: int) -> tuple[int, int]:
        return struct.unpack_from("<II", self.data, self.directory_offset + index * 8)

    def rva_to_offset(self, rva: int) -> int:
        if rva < self.size_of_headers:
            return rva
        for sec in self.sections:
            size = max(sec["virtual_size"], sec["raw_size"])
            if sec["virtual_address"] <= rva < sec["virtual_address"] + size:
                return sec["raw_offset"] + (rva - sec["virtual_address"])
        raise ValueError(f"RVA is not mapped: {rva:#x}")

    def static_imports(self) -> list[dict[str, Any]]:
        import_rva, import_size = self.directory(1)
        if not import_rva or not import_size:
            return []
        off = self.rva_to_offset(import_rva)
        result = []
        while off + 20 <= len(self.data):
            original_first_thunk, timestamp, forwarder, name_rva, first_thunk = struct.unpack_from("<IIIII", self.data, off)
            if not any((original_first_thunk, timestamp, forwarder, name_rva, first_thunk)):
                break
            name_off = self.rva_to_offset(name_rva)
            dll = self.data[name_off:self.data.find(b"\0", name_off)].decode("ascii", "replace")
            thunk_rva = original_first_thunk or first_thunk
            thunk_off = self.rva_to_offset(thunk_rva)
            symbols = []
            while thunk_off + 4 <= len(self.data):
                value = u32(self.data, thunk_off)
                if value == 0:
                    break
                if value & 0x80000000:
                    symbols.append({"ordinal": value & 0xFFFF})
                else:
                    hint_name_off = self.rva_to_offset(value)
                    hint = u16(self.data, hint_name_off)
                    end = self.data.find(b"\0", hint_name_off + 2)
                    name = self.data[hint_name_off + 2:end].decode("ascii", "replace")
                    symbols.append({"hint": hint, "name": name})
                thunk_off += 4
            result.append({"dll": dll, "symbols": symbols})
            off += 20
        return result

    def resources(self, output_dir: Path | None = None) -> list[dict[str, Any]]:
        resource_rva, resource_size = self.directory(2)
        if not resource_rva or not resource_size:
            return []
        base = self.rva_to_offset(resource_rva)
        entries: list[dict[str, Any]] = []

        def read_name(value: int) -> str:
            if not (value & 0x80000000):
                return str(value)
            name_off = base + (value & 0x7FFFFFFF)
            length = u16(self.data, name_off)
            return self.data[name_off + 2:name_off + 2 + length * 2].decode("utf-16le", "replace")

        def walk(relative: int, path: list[str]) -> None:
            directory = base + relative
            named_count = u16(self.data, directory + 12)
            id_count = u16(self.data, directory + 14)
            for index in range(named_count + id_count):
                name_value, child_value = struct.unpack_from("<II", self.data, directory + 16 + index * 8)
                name = read_name(name_value)
                if child_value & 0x80000000:
                    walk(child_value & 0x7FFFFFFF, path + [name])
                    continue
                leaf = base + child_value
                data_rva, size, codepage, _ = struct.unpack_from("<IIII", self.data, leaf)
                data_off = self.rva_to_offset(data_rva)
                payload = self.data[data_off:data_off + size]
                item = {
                    "path": path + [name],
                    "type_name": RESOURCE_TYPES.get(int((path + [name])[0]), "UNKNOWN") if (path + [name])[0].isdigit() else "NAMED",
                    "rva": data_rva,
                    "size": size,
                    "codepage": codepage,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
                if output_dir is not None:
                    output_dir.mkdir(parents=True, exist_ok=True)
                    file_name = "_".join(path + [name]) + ".bin"
                    (output_dir / file_name).write_bytes(payload)
                    item["file"] = file_name
                entries.append(item)

        walk(0, [])
        return entries

    def xor11_dynamic_imports(self) -> list[dict[str, str]]:
        """Recover the protected import-name records found in the sample.

        The table stores every byte XORed with 0x11 and alternates DLL and API
        records. Restricting the scan to raw sections avoids unrelated matches.
        """
        decoded = bytes(byte ^ 0x11 for byte in self.data)
        records: list[tuple[int, str]] = []
        for sec in self.sections:
            if not sec["raw_size"]:
                continue
            start = sec["raw_offset"]
            end = start + sec["raw_size"]
            i = start
            while i < end - 4:
                if 32 <= decoded[i] <= 126 and decoded[i + 1] == ord("q"):
                    j = i + 2
                    while j < end and 32 <= decoded[j] <= 126 and j - (i + 2) < 100:
                        j += 1
                    if j < end and decoded[j] == 0 and j > i + 4:
                        token = decoded[i + 2:j].decode("ascii", "ignore")
                        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_@?.-]*", token):
                            records.append((i, token))
                            i = j + 1
                            continue
                i += 1
        current_dll: str | None = None
        imports: list[dict[str, str]] = []
        known_dlls = {
            "advapi32.dll", "avifil32.dll", "comctl32.dll", "comdlg32.dll",
            "gdi32.dll", "iphlpapi.dll", "kernel32.dll", "msimg32.dll",
            "msvfw32.dll", "ole32.dll", "oleaut32.dll", "shell32.dll",
            "user32.dll", "winmm.dll", "winspool.drv", "ws2_32.dll",
        }
        for offset, token in records:
            if token.lower() in known_dlls:
                current_dll = token
            elif current_dll:
                imports.append({"offset": f"0x{offset:08x}", "dll": current_dll, "name": token})
        clusters: list[list[dict[str, str]]] = []
        for item in imports:
            if not clusters or int(item["offset"], 16) - int(clusters[-1][-1]["offset"], 16) > 0x100:
                clusters.append([item])
            else:
                clusters[-1].append(item)
        return max(clusters, key=len, default=[])


def extract_utf16_strings(data: bytes, min_chars: int = 3) -> list[str]:
    pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_chars)
    return [match.group(0).decode("utf-16le", "replace") for match in pattern.finditer(data)]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", type=Path, default=Path("analysis-output"))
    parser.add_argument("--extract-resources", action="store_true")
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    pe = PE(args.input)
    resource_dir = args.out / "resources" if args.extract_resources else None
    resources = pe.resources(resource_dir)
    static_imports = pe.static_imports()
    dynamic_imports = pe.xor11_dynamic_imports()
    counts: dict[str, int] = defaultdict(int)
    for item in dynamic_imports:
        counts[item["dll"]] += 1

    entry_file_offset = pe.rva_to_offset(pe.entry_rva)
    entry_bytes = pe.data[entry_file_offset:entry_file_offset + 16]
    entry_jump_target = None
    if entry_bytes[:1] == b"\xE9":
        displacement = struct.unpack_from("<i", entry_bytes, 1)[0]
        entry_jump_target = pe.image_base + pe.entry_rva + 5 + displacement

    report = {
        "sample": {
            "file_name": args.input.name,
            "size": args.input.stat().st_size,
            "md5": sha(args.input, "md5"),
            "sha256": sha(args.input, "sha256"),
        },
        "pe": {
            "format": "PE32",
            "machine": f"0x{pe.machine:04x}",
            "section_count": pe.section_count,
            "timestamp_utc": dt.datetime.fromtimestamp(pe.timestamp, dt.timezone.utc).isoformat(),
            "image_base": f"0x{pe.image_base:08x}",
            "entry_rva": f"0x{pe.entry_rva:08x}",
            "entry_va": f"0x{pe.image_base + pe.entry_rva:08x}",
            "entry_file_offset": f"0x{entry_file_offset:08x}",
            "entry_bytes": entry_bytes.hex(),
            "entry_jump_target_va": f"0x{entry_jump_target:08x}" if entry_jump_target is not None else None,
            "size_of_image": pe.size_of_image,
            "subsystem": pe.subsystem,
            "clr_directory": {"rva": pe.directory(14)[0], "size": pe.directory(14)[1]},
        },
        "sections": pe.sections,
        "static_imports": static_imports,
        "dynamic_imports_xor11": {
            "count": len(dynamic_imports),
            "dll_counts": dict(sorted(counts.items(), key=lambda item: item[0].lower())),
        },
        "resources": resources,
    }
    (args.out / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), "utf-8")
    (args.out / "dynamic_imports_xor11.json").write_text(json.dumps(dynamic_imports, ensure_ascii=False, indent=2), "utf-8")
    with (args.out / "dynamic_imports_xor11.tsv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["offset", "dll", "name"], delimiter="\t")
        writer.writeheader()
        writer.writerows(dynamic_imports)
    with (args.out / "sections.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=pe.sections[0].keys())
        writer.writeheader()
        writer.writerows(pe.sections)

    if resource_dir:
        for item in resources:
            if item["path"][0] == "24":
                payload = (resource_dir / item["file"]).read_bytes()
                (args.out / "manifest.xml").write_bytes(payload)
            if item["path"][0] == "16":
                payload = (resource_dir / item["file"]).read_bytes()
                strings = extract_utf16_strings(payload)
                (args.out / "version_strings.txt").write_text("\n".join(strings) + "\n", "utf-8")

    print(json.dumps({
        "report": str(args.out / "report.json"),
        "dynamic_import_count": len(dynamic_imports),
        "resource_count": len(resources),
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
