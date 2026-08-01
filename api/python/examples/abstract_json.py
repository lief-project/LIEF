#!/usr/bin/env python3
"""Dump the *abstract* view of a binary (ELF / PE / Mach-O) as JSON.

The abstract layer exposes the subset of information shared by every
supported executable format (sections, symbols, relocations, ...). This
script parses the input file, converts its abstract representation to
JSON via ``lief.to_json`` and pretty-prints it.

Example:

    $ python abstract_json.py /bin/ls
"""

import argparse
import json
import sys

import lief


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("binary", help="Path to an ELF, PE or Mach-O binary")
    args = parser.parse_args()

    binary = lief.parse(args.binary)
    if binary is None:
        print(f"Error: failed to parse '{args.binary}'", file=sys.stderr)
        return 1
    if isinstance(binary, lief.COFF.Binary):
        print("COFF objects do not expose an abstract view", file=sys.stderr)
        return 1

    json_data = json.loads(lief.to_json(binary.abstract))
    print(json.dumps(json_data, sort_keys=True, indent=4))
    return 0


if __name__ == "__main__":
    sys.exit(main())
