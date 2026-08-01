#!/usr/bin/env python
"""Dump an ELF binary as JSON.

Parses an ELF file and writes a pretty-printed JSON dump of the full
structure (header, sections, segments, dynamic entries, symbols, ...)
using ``lief.to_json``.

Example:

    $ python elf_json.py /bin/ls
"""

import argparse
import json
import sys

import lief


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("binary", help="Path to an ELF binary")
    args = parser.parse_args()

    binary = lief.ELF.parse(args.binary)
    if binary is None:
        print(f"Error: failed to parse '{args.binary}' as ELF", file=sys.stderr)
        return 1

    json_data = json.loads(lief.to_json(binary))
    print(json.dumps(json_data, sort_keys=True, indent=4))
    return 0


if __name__ == "__main__":
    sys.exit(main())
