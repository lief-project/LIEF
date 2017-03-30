#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Description
# -----------
# Print informations about a Mach-O binary

from lief import MachO

import sys

def read_fit_binary(binary):
    header    = binary.header
    commands  = binary.commands
    libraries = binary.libraries
    sections  = binary.sections
    segments  = binary.segments

    format_str = "{:<33} {:<30}"
    format_hex = "{:<33} 0x{:<28x}"
    format_dec = "{:<33} {:<30d}"

    print("== Header ==")
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
    print(binary.imagebase)

    print("== Commands ==")
    for command in commands:
        print(format_str.format("Type:",    str(command.command).split(".")[-1]))
        print(format_hex.format("Size:",    command.size))
        print(format_hex.format("Offset:",  command.command_offset))
        print("")

    print("== Imported Libraries ==")
    # name timestamp current_version compatibility_version
    f_title = "|{:<30}|{:<10}|{:<16}|{:<22}|"
    f_value = "|{:<30}|{:<10d}|{:<16x}|{:<22x}|"
    print(f_title.format("Name", "Timestamp", "Current Version", "Compatibility Version"))
    for library in libraries:
        print(f_value.format(library.name, library.timestamp, library.current_version, library.compatibility_version))

    print("== Segments ==")
    for segment in segments:
        print(segment.name)
        print(len(segment.content))

    print("== Sections ==")
    for section in sections:
        print(section.type)

    print("== Exported Symbols ==")
    for symbol in binary.exported_symbols:
        print(symbol)


    print("== Imported Symbols ==")
    for symbol in binary.imported_symbols:
        print(symbol)







def read_macho(path_to_binary):
    binaries = MachO.parse(path_to_binary)
    #for binary in binaries:
    read_fit_binary(binaries[0])



if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage:", sys.argv[0], "<Mach-O binary>")
        sys.exit(-1)

    read_macho(sys.argv[1])
