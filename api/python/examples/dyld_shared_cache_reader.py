#!/usr/bin/env python
'''
This script lists libraries embedded in a dyld shared cache file

Note: this script is only working with the extended version of LIEF
'''

import sys
import lief
import argparse
from pathlib import Path
from typing import Optional

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", type=Path,
                        help='Target dyld shared file (file or dir)')
    args = parser.parse_args()

    target: Path = args.target
    if not target.exists():
        print(f"'{target}' does not exist")
        return 1

    dyld_cache = lief.dsc.load(target)
    if dyld_cache is None:
        print(f"Can't parse '{target}'")

    for lib in dyld_cache.libraries:
        print(f"0x{lib.address:016x} {lib.path}")

    for idx, info in enumerate(dyld_cache.mapping_info):
        print(f"mapping_info[{idx:02d}]: [{info.address:016x}, {info.end_address:016x}] -> 0x{info.file_offset:016x}")

    for idx, subcache in enumerate(dyld_cache.subcaches):
        uuid_str = ':'.join(map(lambda e: f"{e:02x}", subcache.uuid))
        print(f"cache[{idx:02d}]: {uuid_str} {subcache.suffix}")

if __name__ == "__main__":
    raise SystemExit(main())
