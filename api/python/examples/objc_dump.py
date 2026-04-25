#!/usr/bin/env python
"""Dump Objective-C metadata of a Mach-O binary.

Parses the Objective-C runtime metadata stored in a Mach-O binary
and prints a header-like declaration of every class (and optionally
every protocol) found.

Note: only available with the extended version of LIEF.

Example:

    $ python objc_dump.py /System/Applications/Calculator.app/Contents/MacOS/Calculator
"""

import argparse
import sys
from pathlib import Path

import lief


def process(filepath: str, skip_protocols: bool = False,
            output_path: str | None = None) -> int:
    target = Path(filepath)
    if not target.is_file():
        print(f"'{target}' is not a valid file", file=sys.stderr)
        return 1

    macho = lief.MachO.parse(target)
    if macho is None:
        print(f"Can't parse Mach-O file: {target}", file=sys.stderr)
        return 1

    metadata = macho.at(0).objc_metadata
    if metadata is None:
        print(f"Can't parse ObjC metadata in '{target}'", file=sys.stderr)
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
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("-o", "--output", help="Output file or directory", default=None)
    parser.add_argument("--skip-protocols", help="Skip ObjC protocols definition",
                        action="store_true")
    parser.add_argument("file", help="Path to the Mach-O binary")
    args = parser.parse_args()

    lief.logging.set_level(lief.logging.LEVEL.WARN)
    return process(args.file, args.skip_protocols, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
