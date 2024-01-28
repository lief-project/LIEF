#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Description
# -----------
# Universal format reader.
# Input can be PE, ELF or Mach-O

import lief
import sys
import argparse
import traceback

class exceptions_handler(object):
    func = None

    def __init__(self, exceptions, on_except_callback=None):
        self.exceptions         = exceptions
        self.on_except_callback = on_except_callback

    def __call__(self, *args, **kwargs):
        if self.func is None:
            self.func = args[0]
            return self
        try:
            return self.func(*args, **kwargs)
        except self.exceptions as e:
            if self.on_except_callback is not None:
                self.on_except_callback(e)
            else:
                print("-" * 60)
                print("Exception in {}: {}".format(self.func.__name__, e))
                exc_type, exc_value, exc_traceback = sys.exc_info()
                traceback.print_tb(exc_traceback)
                print("-" * 60)



@exceptions_handler(Exception)
def print_header(binary):
    header = binary.header

    print("== Header ==\n")
    format_str = "{:<15} {:<30}"
    format_hex = "{:<15} 0x{:<13x}"
    format_dec = "{:<15} {:<30d}"


    modes_str = " - ".join([str(m).split(".")[-1] for m in header.modes])
    bitness = ""
    if header.is_32:
        bitness = "32-bits"

    if header.is_64:
        bitness = "64-bits"


    print(format_str.format("Architecture:", str(header.architecture).split(".")[-1]))
    print(format_str.format("Modes:",        modes_str))
    print(format_hex.format("Entrypoint:",   header.entrypoint))
    print(format_str.format("Object type:",  str(header.object_type).split(".")[-1]))
    print(format_str.format("Endianness:",   str(header.endianness).split(".")[-1]))
    print(format_str.format("Bitness:",      bitness))
    print("")


@exceptions_handler(Exception)
def print_sections(binary):
    print("== Sections ==")
    f_title = "|{:<30} | {:<18}| {:<18}| {:<18}| {:<9}|"
    f_value = "|{:<30} | 0x{:<16x}| 0x{:<16x}| 0x{:<16x}| {:<9.2f}|"
    print(f_title.format("Name", "File offset", "Size", "Virtual Address", "Entropy"))
    for section in binary.sections:
        print(f_value.format(\
                section.name,\
                section.offset,\
                section.size,\
                section.virtual_address,\
                section.entropy))
    print("")


@exceptions_handler(Exception)
def print_relocations(binary):
    print("== Relocations ==")
    f_title = "|{:<18} | {:<6}|"
    f_value = "|0x{:<16x} | {:<6d}|"
    print(f_title.format("Address", "Size"))
    for relocation in binary.relocations:
        print(f_value.format(\
                relocation.address,\
                relocation.size))
    print("")

@exceptions_handler(Exception)
def print_symbols(binary):

    print("== Symbols ==")

    f = "|{:<30} |"

    print(f.format("Name"))

    for symbol in binary.symbols:
        print(f.format(symbol.name))
    print("")


@exceptions_handler(Exception)
def print_exported_functions(binary):

    print("== Exported functions ==")
    f = "|{:<30} |"
    print(f.format("Name"))
    for func in binary.exported_functions:
            print(f.format(func))
    print("")

@exceptions_handler(Exception)
def print_imported_functions(binary):

    print("== Imported functions ==")
    f = "|{:<30} |"
    print(f.format("Name"))
    for func in binary.imported_functions:
        print(f.format(func))
    print("")


@exceptions_handler(Exception)
def print_imported_libraries(binary):

    print("== Imported Libraries ==")
    f = "|{:<30} |"
    print(f.format("Name"))
    for library in binary.libraries:
        print(f.format(library))
    print("")

def main():
    parser = argparse.ArgumentParser(usage='%(prog)s [options] <elf-pe-macho>')
    parser.add_argument('-a', '--all',
            action='store_true', dest='show_all',
            help='Show all information')

    parser.add_argument('-H', '--header',
            action='store_true', dest='show_header',
            help='Display header')

    parser.add_argument('-i', '--imported',
            action='store_true', dest='show_imported_functions',
            help='Display imported functions')

    parser.add_argument('-L', '--libraries',
            action='store_true', dest='show_libraries',
            help='Display Imported Libraries')

    parser.add_argument('-r', '--relocations',
            action='store_true', dest='show_relocs',
            help='Display the relocations (if present)')

    parser.add_argument('-s', '--symbols',
            action='store_true', dest='show_symbols',
            help='Display Symbols')

    parser.add_argument('-S', '--sections',
            action='store_true', dest='show_sections',
            help='Display Sections')

    parser.add_argument('-x', '--exported',
            action='store_true', dest='show_exported_functions',
            help='Display exported functions')

    parser.add_argument("binary",
            metavar="<elf-pe-macho>",
            help='Target File')

    args = parser.parse_args()

    binary = lief.parse(args.binary)

    binary = binary.abstract
    if args.show_header or args.show_all:
        print_header(binary)

    if (args.show_imported_functions or args.show_all) and len(binary.imported_functions) > 0:
        print_imported_functions(binary)

    if (args.show_exported_functions or args.show_all) and len(binary.exported_functions) > 0:
        print_exported_functions(binary)

    if (args.show_libraries or args.show_all) and len(binary.libraries) > 0:
        print_imported_libraries(binary)

    if (args.show_sections or args.show_all) and len(binary.sections) > 0:
        print_sections(binary)

    if (args.show_symbols or args.show_all) and len(binary.symbols) > 0:
        print_symbols(binary)

    if (args.show_relocs or args.show_all) and len(binary.relocations) > 0:
        print_relocations(binary)

if __name__ == "__main__":
    main()



