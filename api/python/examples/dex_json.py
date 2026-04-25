#!/usr/bin/env python
"""Dump a DEX file (Android Dalvik bytecode) as JSON.

Parses a ``.dex`` file and writes a pretty-printed JSON dump of its
structure (header, classes, methods, strings, ...) using
``lief.to_json``.

Example:

    $ python dex_json.py classes.dex
"""

import argparse
import json
import sys

import lief


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("file", help="Path to a DEX file")
    args = parser.parse_args()

    if not lief.is_dex(args.file):
        print(f"'{args.file}' is not a DEX file", file=sys.stderr)
        return 1

    dexfile = lief.DEX.parse(args.file)
    if dexfile is None:
        print(f"Error: failed to parse '{args.file}'", file=sys.stderr)
        return 1

    json_data = json.loads(lief.to_json(dexfile))
    print(json.dumps(json_data, sort_keys=True, indent=4))
    return 0


if __name__ == "__main__":
    sys.exit(main())
