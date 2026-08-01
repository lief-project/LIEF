#!/usr/bin/env python
"""Format-agnostic JSON dump.

Dispatches to ``lief.parse`` and pretty-prints the full JSON
representation of the loaded binary (ELF, PE, Mach-O, COFF, OAT). Use
one of the format-specific ``*_json.py`` scripts when the target type
is known in advance.

Example:

    $ python json_dump.py /bin/ls
"""

import argparse
import json
import sys

import lief


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("file", help="Path to a binary supported by LIEF")
    args = parser.parse_args()

    binary = lief.parse(args.file)
    if binary is None:
        print(f"Error: failed to parse '{args.file}'", file=sys.stderr)
        return 1
    if isinstance(binary, lief.COFF.Binary):
        print("COFF objects are not supported by lief.to_json", file=sys.stderr)
        return 1

    json_data = json.loads(lief.to_json(binary))
    print(json.dumps(json_data, sort_keys=True, indent=4))
    return 0


if __name__ == "__main__":
    sys.exit(main())
