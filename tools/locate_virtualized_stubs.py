#!/usr/bin/env python3
"""Locate direct relative jumps into a common dispatcher in raw PE sections."""
from __future__ import annotations
import argparse, json, struct, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_pe import PE


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("exe", type=Path)
    ap.add_argument("--dispatcher", required=True, help="absolute VA, e.g. 0x58b0b0d")
    ap.add_argument("-o", "--output", type=Path)
    args = ap.parse_args()

    pe = PE(args.exe)
    target = int(args.dispatcher, 0)
    hits = []
    for section in pe.sections:
        raw_size = int(section["raw_size"])
        if not raw_size:
            continue
        raw_offset = int(section["raw_offset"])
        section_rva = int(section.get("rva", section.get("virtual_address")))
        raw = pe.data[raw_offset:raw_offset + raw_size]
        base_va = pe.image_base + section_rva
        for index in range(len(raw) - 4):
            if raw[index] != 0xE9:
                continue
            relative = struct.unpack_from("<i", raw, index + 1)[0]
            destination = base_va + index + 5 + relative
            if destination == target:
                hits.append({
                    "section": section["name"],
                    "va": hex(base_va + index),
                    "file_offset": hex(raw_offset + index),
                    "preceding_24": raw[max(0, index - 24):index].hex(),
                })

    result = {"dispatcher_va": hex(target), "hit_count": len(hits), "hits": hits}
    text = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text)


if __name__ == "__main__":
    main()
