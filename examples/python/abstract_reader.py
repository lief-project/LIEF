#/usr/bin/env python
# -*- coding: utf-8 -*-

# Description
# -----------
# Universal format reader.
# Input can be PE, ELF or Mach-O

import lief
import sys

def print_sections(sections):
    print("== Sections ==")
    f_title = "|{:<30} | {:<18}| {:<18}| {:<18}| {:<9}|"
    f_value = "|{:<30} | 0x{:<16x}| 0x{:<16x}| 0x{:<16x}| {:<9.2f}|"
    print(f_title.format("Name", "File offset", "Size", "Virtual Address", "Entropy"))
    for section in sections:
        print(f_value.format(\
                section.name,\
                section.offset,\
                section.size,\
                section.virtual_address,\
                section.entropy))
    print("")

def print_symbols(symbols):

    print("== Symbols ==")

    f = "|{:<30} |"

    print(f.format("Name"))

    for symbol in symbols:
        print(f.format(symbol.name))
    print("")


def print_exported_functions(functions):

    print("== Exported functions ==")
    f = "|{:<30} |"
    print(f.format("Name"))
    for func in functions:
            print(f.format(func))
    print("")

def print_imported_functions(functions):

    print("== Imported functions ==")
    f = "|{:<30} |"
    print(f.format("Name"))
    for func in functions:
        print(f.format(func))
    print("")


def print_imported_libraries(libraries):

    print("== Imported Libraries ==")
    f = "|{:<30} |"
    print(f.format("Name"))
    for library in libraries:
        print(f.format(library))
    print("")



def read_binary(path):
    print("== Abstract Reader ==")

    binary = lief.parse(path).abstract
    header = binary.header
    print(header)

    sections      = binary.sections
    symbols       = binary.symbols
    func_exported = binary.exported_functions
    func_imported = binary.imported_functions
    libraries     = binary.libraries

    if len(sections) > 0:
        print_sections(sections)

    if len(symbols) > 0:
        print_symbols(symbols)

    if len(func_exported) > 0:
        print_exported_functions(func_exported)

    if len(func_imported) > 0:
        print_imported_functions(func_imported)

    if len(libraries) > 0:
        print_imported_libraries(libraries)



if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage:", sys.argv[0], "<binary>")
        sys.exit(1)

    read_binary(sys.argv[1])

