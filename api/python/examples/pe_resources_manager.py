#!/usr/bin/env python
"""Dump the resource tree and manifest of a PE binary.

Uses ``lief.PE.ResourcesManager`` to render a friendly view of the
``.rsrc`` section followed by the XML manifest embedded in the
binary (when present).

Example:

    $ python pe_resources_manager.py C:\\Windows\\explorer.exe
"""

import argparse
import sys

import lief


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("binary", help="Path to a PE binary")
    args = parser.parse_args()

    pe = lief.PE.parse(args.binary)
    if pe is None:
        print(f"Error: failed to parse '{args.binary}' as PE", file=sys.stderr)
        return 1

    manager = pe.resources_manager
    if not isinstance(manager, lief.PE.ResourcesManager):
        print("Error: failed to access the resource manager")
        return 1

    print(manager)
    print(manager.manifest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
