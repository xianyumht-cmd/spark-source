#!/usr/bin/env python3
"""Extract PE32 resources without external packages.

Version-resource strings are omitted from the JSON index by default so the
result contains only technical metadata. Binary resources are written as-is.
"""
from __future__ import annotations
import argparse, hashlib, json, struct
from pathlib import Path

TYPES = {3: "ICON", 14: "GROUP_ICON", 16: "VERSION", 24: "MANIFEST"}


def extract(src: Path, out: Path) -> dict:
    blob = src.read_bytes()
    u16 = lambda o: struct.unpack_from("<H", blob, o)[0]
    u32 = lambda o: struct.unpack_from("<I", blob, o)[0]
    pe = u32(0x3C); coff = pe + 4; opt = coff + 20
    count = u16(coff + 2); opt_size = u16(coff + 16)
    sections = []
    for i in range(count):
        off = opt + opt_size + i * 40
        sections.append((u32(off + 12), max(u32(off + 8), u32(off + 16)), u32(off + 20)))

    def rva_to_offset(rva: int) -> int:
        for base, size, raw in sections:
            if base <= rva < base + size:
                return raw + rva - base
        raise ValueError(f"RVA not mapped: 0x{rva:x}")

    resource_rva = u32(opt + 96 + 2 * 8)
    resource_size = u32(opt + 96 + 2 * 8 + 4)
    root = rva_to_offset(resource_rva)
    out.mkdir(parents=True, exist_ok=True)
    items = []

    def decode_name(value: int):
        if value & 0x80000000:
            pos = root + (value & 0x7FFFFFFF)
            chars = u16(pos)
            return blob[pos + 2:pos + 2 + chars * 2].decode("utf-16le", "replace")
        return value

    def walk(relative: int, path: list):
        directory = root + relative
        entries = u16(directory + 12) + u16(directory + 14)
        for index in range(entries):
            item = directory + 16 + index * 8
            name = decode_name(u32(item)); target = u32(item + 4)
            current = path + [name]
            if target & 0x80000000:
                walk(target & 0x7FFFFFFF, current)
                continue
            data_entry = root + target
            data_rva, size, codepage = u32(data_entry), u32(data_entry + 4), u32(data_entry + 8)
            payload_offset = rva_to_offset(data_rva)
            payload = blob[payload_offset:payload_offset + size]
            resource_type = current[0]
            type_name = TYPES.get(resource_type, str(resource_type))
            suffix = {3: ".icoimg", 14: ".groupicon", 16: ".version.bin", 24: ".manifest"}.get(resource_type, ".bin")
            filename = f"{type_name}_{'_'.join(map(str, current))}{suffix}"
            (out / filename).write_bytes(payload)
            items.append({
                "path": current, "type_name": type_name, "rva": data_rva,
                "size": size, "codepage": codepage, "sha256": hashlib.sha256(payload).hexdigest(),
                "file": filename,
            })

    walk(0, [])
    result = {"resource_rva": resource_rva, "resource_size": resource_size, "items": items}
    (out / "resources-index.sanitized.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(json.dumps(extract(args.input, args.output), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
