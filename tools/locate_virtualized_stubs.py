#!/usr/bin/env python3
"""Locate direct relative jumps into a common dispatcher in a PE section."""
from __future__ import annotations
import argparse, json, struct, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_pe import PE

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('exe', type=Path)
    ap.add_argument('--dispatcher', required=True, help='absolute VA, e.g. 0x58b0b0d')
    ap.add_argument('-o', '--output', type=Path)
    a = ap.parse_args()
    pe = PE(a.exe)
    target = int(a.dispatcher, 0)
    hits = []
    for s in pe.sections:
        if not s['raw_size']:
            continue
        raw = pe.data[s['raw_offset']:s['raw_offset'] + s['raw_size']]
        base = pe.image_base + s['rva']
        for i in range(len(raw) - 5):
            if raw[i] != 0xe9:
                continue
            rel = struct.unpack_from('<i', raw, i + 1)[0]
            dst = base + i + 5 + rel
            if dst == target:
                hits.append({
                    'section': s['name'],
                    'va': hex(base + i),
                    'file_offset': hex(s['raw_offset'] + i),
                    'preceding_24': raw[max(0, i - 24):i].hex(),
                })
    obj = {'dispatcher_va': hex(target), 'hit_count': len(hits), 'hits': hits}
    text = json.dumps(obj, indent=2)
    if a.output:
        a.output.write_text(text, encoding='utf-8')
    else:
        print(text)

if __name__ == '__main__':
    main()
