#!/usr/bin/env python
"""Format-agnostic ``nm``-style symbol lister.

Prints every symbol found in a binary. For PE files, it prints the
entries of the *symbol section*; for ELF files, both the static
(``.symtab``) and dynamic (``.dynsym``) symbols; for Mach-O the
global symbol table.

Example:

    $ python nm.py /usr/bin/ls
"""

import argparse
import sys

import lief


def nm(filename: str) -> int:
    binary = lief.parse(filename)
    if binary is None:
        print(f"Error: failed to parse '{filename}'", file=sys.stderr)
        return 1

    symbols = binary.symbols
    if len(symbols) > 0:
        for symbol in symbols:
            print(symbol)
    else:
        print("No symbols found")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("binary", help="Path to the binary to list")
    args = parser.parse_args()
    return nm(args.binary)


if __name__ == "__main__":
    sys.exit(main())
