#!/usr/bin/env python3
"""Dependency-free PE32 layout and entropy scanner."""
from __future__ import annotations
import argparse, collections, hashlib, json, math, struct
from pathlib import Path


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    size = len(data)
    return -sum((n / size) * math.log2(n / size) for n in counts.values())


def scan(path: Path) -> dict:
    data = path.read_bytes()
    u16 = lambda off: struct.unpack_from("<H", data, off)[0]
    u32 = lambda off: struct.unpack_from("<I", data, off)[0]
    if data[:2] != b"MZ":
        raise ValueError("not an MZ executable")
    pe = u32(0x3C)
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("invalid PE signature")
    coff = pe + 4
    count = u16(coff + 2)
    opt_size = u16(coff + 16)
    opt = coff + 20
    if u16(opt) != 0x10B:
        raise ValueError("this scanner currently expects PE32")
    section_table = opt + opt_size
    sections = []
    for i in range(count):
        off = section_table + i * 40
        name = data[off:off + 8].split(b"\0", 1)[0].decode("latin1")
        virtual_size, rva, raw_size, raw_pointer = struct.unpack_from("<IIII", data, off + 8)
        characteristics = u32(off + 36)
        raw = data[raw_pointer:raw_pointer + raw_size] if raw_size else b""
        sections.append({
            "name": name, "virtual_size": virtual_size, "rva": rva,
            "raw_size": raw_size, "raw_pointer": raw_pointer,
            "characteristics": f"0x{characteristics:08x}",
            "entropy": round(entropy(raw), 6),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
    image_base = u32(opt + 28)
    entry_rva = u32(opt + 16)
    return {
        "path": str(path), "file_size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "machine": f"0x{u16(coff):04x}", "section_count": count,
        "image_base": image_base, "entry_rva": entry_rva,
        "entry_va": image_base + entry_rva,
        "size_of_image": u32(opt + 56), "sections": sections,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(scan(args.input), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(result, encoding="utf-8")
    else:
        print(result, end="")


if __name__ == "__main__":
    main()
