#!/usr/bin/env python
"""Obfuscate ``.symtab`` entries by renaming them to random strings.

Replaces every static (``.symtab``) symbol name with a random
lowercase string of the same length. Useful to hinder naive symbolic
analysis while preserving binary layout.

Example:

    $ readelf -s ./hello_c | head -3
        29: 0400420 0 FUNC LOCAL DEFAULT 12 deregister_tm_clones
    $ python elf_symbol_obfuscation.py ./hello_c ./hello_c.obf
    $ readelf -s ./hello_c.obf | head -3
        29: 0400420 0 FUNC LOCAL DEFAULT 12 wsadqwrubbmdugrxzwiv
"""

import argparse
import random
import string
import sys

import lief


def randomword(length: int) -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(length))


def randomize(binary: lief.ELF.Binary, output: str) -> int:
    symbols = binary.symtab_symbols
    if len(symbols) == 0:
        print("No symbols", file=sys.stderr)
        return 1
    for symbol in symbols:
        symbol.name = randomword(len(symbol.name))
    binary.write(output)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("input", metavar="<elf>", help="Input ELF binary")
    parser.add_argument("output", metavar="<out>", help="Output obfuscated binary")
    args = parser.parse_args()

    binary = lief.ELF.parse(args.input)
    if binary is None:
        print(f"Error: failed to parse '{args.input}' as ELF", file=sys.stderr)
        return 1

    return randomize(binary, args.output)


if __name__ == "__main__":
    sys.exit(main())
