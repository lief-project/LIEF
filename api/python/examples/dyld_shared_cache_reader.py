#!/usr/bin/env python
"""List the contents of a dyld shared cache.

Loads an Apple ``dyld`` shared cache (single file or multi-file
directory layout) and prints the embedded libraries, the mapping
information for each page range and the UUID of the sub-caches.

Note: only available with the extended version of LIEF.

Example:

    $ python dyld_shared_cache_reader.py /System/Library/dyld/dyld_shared_cache_arm64e
"""

import argparse
import sys
from pathlib import Path

import lief


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "target", type=Path, help="Target dyld shared cache file or directory"
    )
    args = parser.parse_args()

    target: Path = args.target
    if not target.exists():
        print(f"'{target}' does not exist", file=sys.stderr)
        return 1

    dyld_cache = lief.dsc.load(target)
    if dyld_cache is None:
        print(f"Can't parse '{target}'", file=sys.stderr)
        return 1

    for lib in dyld_cache.libraries:
        print(f"{lib.address:#016x} {lib.path}")

    for idx, info in enumerate(dyld_cache.mapping_info):
        print(
            f"mapping_info[{idx:02d}]: "
            f"[{info.address:#016x}, {info.end_address:#016x}] -> "
            f"{info.file_offset:#016x}"
        )

    for idx, subcache in enumerate(dyld_cache.subcaches):
        uuid_str = ":".join(f"{e:02x}" for e in subcache.uuid)
        print(f"cache[{idx:02d}]: {uuid_str} {subcache.suffix}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
