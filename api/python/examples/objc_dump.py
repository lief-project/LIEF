#!/usr/bin/env python
'''
This script dumps the Objective-C metadata from the provided binary and
generate a header-like of different structure identified.

Note: this script is only working with the extended version of LIEF
'''

import sys
import lief
import argparse
from pathlib import Path
from typing import Optional

def process(filepath: str, skip_protocols: bool = False,
            output_path: Optional[str] = None) -> int:
    target = Path(filepath)
    if not target.is_file():
        print(f"'{target}' is not a valid file", file=sys.stderr)
        return 1

    macho = lief.MachO.parse(target)
    if macho is None:
        print(f"Can't parse Mach-O file: {target}", file=sys.stderr)
    metadata = macho.at(0).objc_metadata

    if metadata is None:
        print(f"Can't parse ObjC metadata in {target}'", file=sys.stderr)
        return 1

    if skip_protocols:
        output = ""
        for cls in metadata.classes:
            output += cls.to_decl()
    else:
        output = metadata.to_decl()
    print(output)

    if output_path is not None:
        out = Path(output_path)
        if out.is_dir():
            out /= f"{target.name}_objc.h"
            out.write_text(output)
            print(f"Saved in {out}")
        else:
            print(f"Saved in {out}")
            out.write_text(output)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output',
                        help='Output file',
                        default=None)
    parser.add_argument('--skip-protocols',
                        help='Skip ObjC protocols definition',
                        action='store_true')
    parser.add_argument("file", help='Mach-O file')
    args = parser.parse_args()

    lief.logging.set_level(lief.logging.LEVEL.WARN)
    return process(args.file, args.skip_protocols, args.output)

if __name__ == "__main__":
    raise SystemExit(main())
