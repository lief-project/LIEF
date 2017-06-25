#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Description
# -----------
# Print information about a Mach-O binary

import sys
import os
import argparse

from lief import MachO

terminal_rows, terminal_columns = 100, 100
try:
    terminal_rows, terminal_columns = os.popen('stty size', 'r').read().split()
except ValueError:
    pass

terminal_columns = int(terminal_columns)
terminal_rows    = int(terminal_rows)

def print_information(binary):
    print("== Information ==")
    format_str = "{:<30} {:<30}"
    format_hex = "{:<30} 0x{:<28x}"
    format_dec = "{:<30} {:<30d}"
    print(format_str.format("Name:",         binary.name))
    print(format_hex.format("Address base:", binary.imagebase))
    print("")

def print_header(binary):
    format_str = "{:<33} {:<30}"
    format_hex = "{:<33} 0x{:<28x}"
    format_dec = "{:<33} {:<30d}"

    print("== Header ==")
    header = binary.header
    flags = ""
    for flag in header.flags:
        flag = str(flag).split(".")[-1]
        flags += (flag if len(flags) == 0 else " - " + flag)

    print(format_hex.format("Magic:",              header.magic))
    print(format_str.format("CPU Type:",           str(header.cpu_type).split(".")[-1]))
    print(format_hex.format("CPU sub-type:",       header.cpu_subtype))
    print(format_str.format("File Type:",          str(header.file_type).split(".")[-1]))
    print(format_str.format("Flags:",              flags))
    print(format_dec.format("Number of commands:", header.nb_cmds))
    print(format_hex.format("Size of commands:",   header.sizeof_cmds))
    print(format_hex.format("Reserved:",           header.reserved))

def print_commands(binary):

    f_title = "|{:<20}|{:<11}|{:<11}|"
    f_value = "|{:<20}|0x{:08x} |0x{:08x} |"
    print("== Commands ==")
    print(f_title.format("Command", "Offset", "Size"))
    for command in binary.commands:
        print(f_value.format(
            str(command.command).split(".")[-1],
            command.command_offset,
            command.size))
    print("")

def print_libraries(binary):

    f_title = "|{:<30}|{:<10}|{:<16}|{:<22}|"
    f_value = "|{:<30}|{:<10d}|{:<16x}|{:<22x}|"
    print("== Libraries ==")
    print(f_title.format("Name", "Timestamp", "Current Version", "Compatibility Version"))
    for library in binary.libraries:
        print(f_value.format(
            library.name,
            library.timestamp,
            library.current_version,
            library.compatibility_version))
    print("")

def print_segments(binary):

    f_title = "|{:<20}|{:<16}|{:<16}|{:<16}|{:16}|{:16}|{:16}|{}"
    f_value = "|{:<20}|0x{:<13x} |0x{:<13x} |0x{:<13x} |0x{:<13x} |0x{:<13x} |0x{:<13x} |{}"
    print("== Segments ==")
    print(f_title.format(
        "Name", "Virtual Address", "Virtual Size",
        "Offset", "Size", "Max Protection",
        "Init Protection", "Sections"))
    for segment in binary.segments:
        sections = ", ".join(map(lambda s : s.name, segment.sections))
        print(f_value.format(
            segment.name,
            segment.virtual_address,
            segment.virtual_size,
            segment.file_size,
            segment.file_offset,
            segment.max_protection,
            segment.init_protection,
            sections))
    print("")

def print_sections(binary):

    f_title = "|{:<20}|{:<16}|{:<16}|{:<16}|{:16}|{:22}|{:19}|{:25}|"
    f_value = "|{:<20}|0x{:<13x} |0x{:<13x} |0x{:<13x} |0x{:<13x} |0x{:<19x} |0x{:<16x} |{:<25}|"
    print("== Sections ==")
    print(f_title.format(
        "Name", "Virtual Address", "Offset", "Size",
        "Alignement", "Number of Relocations", "Relocation offset",
        "Type"))
    for section in binary.sections:
        print(f_value.format(
            section.name,
            section.virtual_address,
            section.offset,
            section.size,
            section.alignment,
            section.numberof_relocations,
            section.relocation_offset,
            str(section.type).split(".")[-1]))
    print("")

def print_symbols(binary):
    symbols = binary.symbols
    if len(symbols) == 0:
        return
    try:
        maxsize = max([len(symbol.demangled_name) for symbol in symbols])
    except:
        maxsize = max([len(symbol.name) for symbol in symbols])
    maxsize = min(maxsize, terminal_columns - 90) if terminal_columns > 90 else terminal_columns

    f_title = "|{:<" + str(maxsize) + "} |{:<6}|{:<19}|{:<16}|{:16}|"
    f_value = "|{:<" + str(maxsize) + "} |0x{:<3x} |0x{:<16x} |0x{:<13x} |0x{:<13x} |"
    print("== Symbols ==")
    print(f_title.format(
        "Name", "Type", "Number of Sections", "Description", "Value"))
    for symbol in binary.symbols:

        try:
            symbol_name = symbol.demangled_name
        except:
            symbol_name = symbol.name
        print(f_value.format(
            symbol_name,
            symbol.type,
            symbol.numberof_sections,
            symbol.description,
            symbol.value))
    print("")


def print_uuid(binary):
    print("== UUID ==")
    cmd = binary.uuid
    uuid_str = " ".join(map(lambda e : "{:02x}".format(e), cmd.uuid))
    print("UUID: {}".format(uuid_str))


def print_main_command(binary):

    format_str = "{:<13} {:<30}"
    format_hex = "{:<13} 0x{:<28x}"
    format_dec = "{:<13} {:<30d}"

    print("== Main Command ==")
    cmd = binary.main_command

    print(format_hex.format("Entry point:", cmd.entrypoint))
    print(format_hex.format("Stack size:", cmd.stack_size))


def print_dylinker(binary):
    print("== Dylinker ==")
    print("Path: {}".format(binary.dylinker.name))


def main():
    parser = argparse.ArgumentParser(usage='%(prog)s [options] <macho-file>')
    parser.add_argument('-a', '--all',
            action='store_true', dest='show_all',
            help='Show all information')

    parser.add_argument('-c', '--commands',
            action='store_true', dest='show_commands',
            help='Display Commands')

    parser.add_argument('-H', '--header',
            action='store_true', dest='show_header',
            help='Display header')

    parser.add_argument('-L', '--libraries',
            action='store_true', dest='show_libraries',
            help='Display Imported Libraries')

    parser.add_argument('-l', '--segments',
            action='store_true', dest='show_segments',
            help='Display Segments')

    parser.add_argument('-s', '--symbols',
            action='store_true', dest='show_symbols',
            help='Display Symbols')

    parser.add_argument('-S', '--sections',
            action='store_true', dest='show_sections',
            help='Display Sections')

    parser.add_argument('--uuid',
            action='store_true', dest='show_uuid',
            help='Display the UUID command')

    parser.add_argument('--main',
            action='store_true', dest='show_main',
            help='Display the Main command')

    parser.add_argument('--dylinker',
            action='store_true', dest='show_dylinker',
            help='Display the Dylinker command')

    parser.add_argument("binary",
            metavar="<macho-file>",
            help='Target Mach-O File')

    args = parser.parse_args()


    binaries = None
    try:
        binaries = MachO.parse(args.binary)
    except lief.exception as e:
        print(e)
        sys.exit(1)

    for binary in binaries:
        print_information(binary)

        if args.show_header or args.show_all:
            print_header(binary)

        if args.show_commands or args.show_all:
            print_commands(binary)

        if args.show_libraries or args.show_all:
            print_libraries(binary)

        if args.show_segments or args.show_all:
            print_segments(binary)

        if args.show_sections or args.show_all:
            print_sections(binary)

        if args.show_symbols or args.show_all:
            print_symbols(binary)

        if (args.show_uuid or args.show_all) and binary.has_uuid:
            print_uuid(binary)

        if (args.show_main or args.show_all) and binary.has_main_command:
            print_main_command(binary)

        if (args.show_dylinker or args.show_all) and binary.has_dylinker:
            print_dylinker(binary)


if __name__ == "__main__":
    main()
