#!/usr/bin/env python3
"""Rebuild ICO files from RT_ICON and RT_GROUP_ICON resource blobs."""
from __future__ import annotations
import argparse
import struct
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('resource_dir', type=Path)
    ap.add_argument('--out', type=Path, default=Path('icons'))
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    icons: dict[int, bytes] = {}
    for path in args.resource_dir.glob('3_*_*.bin'):
        try:
            icons[int(path.stem.split('_')[1])] = path.read_bytes()
        except (ValueError, IndexError):
            continue
    for group in args.resource_dir.glob('14_*_*.bin'):
        data = group.read_bytes()
        if len(data) < 6:
            continue
        reserved, kind, count = struct.unpack_from('<HHH', data, 0)
        if reserved != 0 or kind != 1 or len(data) < 6 + count * 14:
            continue
        directory = bytearray(struct.pack('<HHH', 0, 1, count))
        payloads: list[bytes] = []
        offset = 6 + count * 16
        for index in range(count):
            width, height, colors, zero, planes, bpp, declared_size, resource_id = struct.unpack_from(
                '<BBBBHHIH', data, 6 + index * 14
            )
            payload = icons.get(resource_id)
            if payload is None:
                raise RuntimeError(f'missing RT_ICON resource {resource_id} for {group.name}')
            directory += struct.pack(
                '<BBBBHHII', width, height, colors, zero, planes, bpp, len(payload), offset
            )
            payloads.append(payload)
            offset += len(payload)
        for payload in payloads:
            directory += payload
        output = args.out / f'{group.stem}.ico'
        output.write_bytes(directory)
        print(output)


if __name__ == '__main__':
    main()
