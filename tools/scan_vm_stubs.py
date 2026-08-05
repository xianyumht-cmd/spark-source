#!/usr/bin/env python3
"""Locate fixed-form VM entry stubs without executing the target."""
from __future__ import annotations

import argparse
import csv
import json
import struct
from collections import Counter
from pathlib import Path


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from('<H', data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from('<I', data, off)[0]


def parse_pe(data: bytes) -> tuple[int, list[dict[str, int | str]]]:
    pe = u32(data, 0x3C)
    if data[:2] != b'MZ' or data[pe:pe + 4] != b'PE\0\0':
        raise ValueError('not a PE image')
    coff = pe + 4
    count = u16(data, coff + 2)
    optional_size = u16(data, coff + 16)
    optional = coff + 20
    if u16(data, optional) != 0x10B:
        raise ValueError('only PE32 is supported')
    image_base = u32(data, optional + 28)
    table = optional + optional_size
    sections = []
    for index in range(count):
        off = table + index * 40
        sections.append({
            'name': data[off:off + 8].rstrip(b'\0').decode('latin1'),
            'virtual_size': u32(data, off + 8),
            'virtual_address': u32(data, off + 12),
            'raw_size': u32(data, off + 16),
            'raw_offset': u32(data, off + 20),
        })
    return image_base, sections


def scan_section(data: bytes, image_base: int, section: dict[str, int | str]) -> list[dict[str, object]]:
    raw_offset = int(section['raw_offset'])
    raw_size = int(section['raw_size'])
    section_rva = int(section['virtual_address'])
    raw = data[raw_offset:raw_offset + raw_size]
    rows = []
    register_names = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']

    for jump_off in range(29, len(raw) - 5):
        if raw[jump_off] != 0xE9:
            continue
        start = jump_off - 29
        stub = raw[start:jump_off]
        if len(stub) != 29 or not all(0x50 <= byte <= 0x57 for byte in stub[:3]):
            continue
        register = stub[3] - 0xB8
        if not 0 <= register <= 7:
            continue
        if stub[8:12] != bytes((0x89, 0x44 + 8 * register, 0x24, 0x08)):
            continue
        if stub[12] != 0xB8 + register:
            continue
        if stub[17:21] != bytes((0x89, 0x44 + 8 * register, 0x24, 0x04)):
            continue
        if stub[21] != 0xB8 + register:
            continue
        if stub[26:29] != bytes((0x87, 0x04 + 8 * register, 0x24)):
            continue

        va = image_base + section_rva + start
        jump_va = image_base + section_rva + jump_off
        dispatcher = jump_va + 5 + struct.unpack_from('<i', raw, jump_off + 1)[0]
        rows.append({
            'file_offset': f'0x{raw_offset + start:08x}',
            'section_offset': f'0x{start:08x}',
            'va': f'0x{va:08x}',
            'pushes': [register_names[byte - 0x50] for byte in stub[:3]],
            'scratch_register': register_names[register],
            'key': f'0x{u32(stub, 4):08x}',
            'slot': f'0x{u32(stub, 13):08x}',
            'vm_target': f'0x{u32(stub, 22):08x}',
            'dispatcher': f'0x{dispatcher:08x}',
        })
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('input', type=Path)
    parser.add_argument('--section', default='.5497y')
    parser.add_argument('--out', type=Path, default=Path('analysis-output'))
    args = parser.parse_args()

    data = args.input.read_bytes()
    image_base, sections = parse_pe(data)
    section = next((item for item in sections if item['name'] == args.section), None)
    if section is None:
        raise SystemExit(f'section not found: {args.section}')
    rows = scan_section(data, image_base, section)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'vm-entry-stubs.json').write_text(json.dumps(rows, ensure_ascii=False, indent=2), 'utf-8')
    with (args.out / 'vm-entry-stubs.csv').open('w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=['file_offset', 'section_offset', 'va', 'pushes', 'scratch_register', 'key', 'slot', 'vm_target', 'dispatcher'])
        writer.writeheader()
        for row in rows:
            writer.writerow({**row, 'pushes': ','.join(row['pushes'])})
    summary = {
        'stub_count': len(rows),
        'dispatcher_counts': dict(Counter(row['dispatcher'] for row in rows)),
        'vm_target_counts': dict(Counter(row['vm_target'] for row in rows)),
        'nonzero_slot_count': sum(int(row['slot'], 16) != 0 for row in rows),
    }
    (args.out / 'vm-entry-summary.json').write_text(json.dumps(summary, indent=2), 'utf-8')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
