#!/usr/bin/env python
"""Dump a VDEX file (Android verified DEX container) as JSON.

Parses a ``.vdex`` file and writes a pretty-printed JSON dump of its
structure using ``lief.to_json``.

Example:

    $ python vdex_json.py primary.vdex
"""

import argparse
import json
import sys

import lief


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("file", help="Path to a VDEX file")
    args = parser.parse_args()

    if not lief.is_vdex(args.file):
        print(f"'{args.file}' is not a VDEX file", file=sys.stderr)
        return 1

    vdexfile = lief.VDEX.parse(args.file)
    if vdexfile is None:
        print(f"Error: failed to parse '{args.file}'", file=sys.stderr)
        return 1

    json_data = json.loads(lief.to_json(vdexfile))
    print(json.dumps(json_data, sort_keys=True, indent=4))
    return 0


if __name__ == "__main__":
    sys.exit(main())
