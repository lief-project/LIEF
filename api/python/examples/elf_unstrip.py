#!/usr/bin/env python
"""Inject a ``.symtab`` entry into a stripped ELF binary.

Adds a fresh ``SYMTAB``/``STRTAB`` section pair and records a single
``FUNC`` symbol (by default ``main`` at ``0x402A00``) so that
debuggers such as ``gdb`` can resolve a symbolic breakpoint on a
binary whose static symbol table was removed.

Example:

    $ python elf_unstrip.py ./stripped ./unstripped
    $ gdb ./unstripped
    (gdb) break main
    Breakpoint 1 at 0x402a00
"""

import argparse
import sys

from lief import ELF


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("input", metavar="<elf>", help="Input (stripped) ELF binary")
    parser.add_argument("output", metavar="<out>", help="Output ELF binary")
    parser.add_argument("--address", type=lambda e: int(e, 0), default=0x402A00,
                        help="Address of the added symbol (default: 0x402A00)")
    parser.add_argument("--name", default="main",
                        help="Name of the added symbol (default: main)")
    args = parser.parse_args()

    binary = ELF.parse(args.input)
    if binary is None:
        print(f"Error: failed to parse '{args.input}' as ELF", file=sys.stderr)
        return 1

    symtab_section = ELF.Section()
    symtab_section.name = ""
    symtab_section.type = ELF.Section.TYPE.SYMTAB
    symtab_section.entry_size = 0x18
    symtab_section.alignment = 8
    symtab_section.link = len(binary.sections) + 1
    symtab_section.content = [0] * 100

    symstr_section = ELF.Section()
    symstr_section.name = ""
    symstr_section.type = ELF.Section.TYPE.STRTAB
    symstr_section.entry_size = 1
    symstr_section.alignment = 1
    symstr_section.content = [0] * 100

    binary.add(symtab_section, loaded=False)
    binary.add(symstr_section, loaded=False)

    null_symbol = ELF.Symbol()
    null_symbol.name = ""
    null_symbol.type = ELF.Symbol.TYPE.NOTYPE
    null_symbol.value = 0
    null_symbol.binding = ELF.Symbol.BINDING.LOCAL
    null_symbol.size = 0
    null_symbol.shndx = 0
    binary.add_symtab_symbol(null_symbol)

    symbol = ELF.Symbol()
    symbol.name = args.name
    symbol.type = ELF.Symbol.TYPE.FUNC
    symbol.value = args.address
    symbol.binding = ELF.Symbol.BINDING.LOCAL
    symbol.shndx = 14
    symbol = binary.add_symtab_symbol(symbol)

    print(symbol)

    binary.write(args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
