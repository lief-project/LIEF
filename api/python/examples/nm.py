#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Description
# -----------
#
# This tool is a cross format Linux nm like. It prints all symbols
# present in the binary. For `PE` it will print symbols in the *symbol section*
# and for `ELF` it will print *static* symbols **AND** *dynamic* symbols.
#
# Example:
#
# >>> nm("/usr/bin/ls")
# >>> nm("C:\\Windows\\explorer.exe")

import sys
from lief import parse

def nm(filename):
    """ Return symbols from *filename* binary """
    binary  = parse(filename) # Build an abstract binary
    symbols = binary.symbols

    if len(symbols) > 0:
        for symbol in symbols:
            print(symbol)
    else:
        print("No symbols found")


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: " + sys.argv[0] + " <binary>")
        sys.exit(-1)

    nm(sys.argv[1])


