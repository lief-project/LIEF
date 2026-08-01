#!/usr/bin/env python
"""Dump a PE binary as JSON.

Parses a PE file and writes a pretty-printed JSON dump of the full
structure (DOS/optional header, sections, imports, exports, resources,
...) using ``lief.to_json``.

Example:

    $ python pe_json.py C:\\\\Windows\\\\explorer.exe
"""

import argparse
import json
import sys

import lief


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("binary", help="Path to a PE binary")
    args = parser.parse_args()

    binary = lief.PE.parse(args.binary)
    if binary is None:
        print(f"Error: failed to parse '{args.binary}' as PE", file=sys.stderr)
        return 1

    json_data = json.loads(lief.to_json(binary))
    print(json.dumps(json_data, sort_keys=True, indent=4))
    return 0


if __name__ == "__main__":
    sys.exit(main())
