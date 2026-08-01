#!/usr/bin/env python
"""List forwarded exports of a PE binary.

Walks the export directory of a PE binary and prints every entry
that is a *forward* (an export whose implementation lives in another
DLL).

Example:

    $ python pe_forwardinfo.py C:\\Windows\\System32\\kernel32.dll
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

    exports = pe.get_export()
    if exports is None:
        print("No export directory")
        return 0

    for e in filter(lambda e: e.is_forwarded, exports.entries):
        fwd = e.forward_information
        print(f"{e.name:<35} -> {fwd.library}.{fwd.function}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
