#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Description
# -----------
# Print information about an ELF binary

import lief
from lief import ELF

import sys
import os
import traceback

from optparse import OptionParser
terminal_rows, terminal_columns = 100, 100
try:
    terminal_rows, terminal_columns = os.popen('stty size', 'r').read().split()
except ValueError:
    pass

terminal_columns = int(terminal_columns)
terminal_rows    = int(terminal_rows)

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
    identity = header.identity


    print("== Header ==\n")
    format_str = "{:<30} {:<30}"
    format_hex = "{:<30} 0x{:<28x}"
    format_dec = "{:<30} {:<30d}"
    format_ide = "{:<30} {:<02x} {:<02x} {:<02x} {:<02x}"
    print(format_ide.format("Magic:",                 identity[0], identity[1], identity[2], identity[3]))
    print(format_str.format("Class:",                 str(header.identity_class).split(".")[-1]))
    print(format_str.format("Endianness:",            str(header.identity_data).split(".")[-1]))
    print(format_str.format("Version:",               str(header.identity_version).split(".")[-1]))
    print(format_str.format("OS/ABI:",                str(header.identity_os_abi).split(".")[-1]))
    print(format_str.format("File Type:",             str(header.file_type).split(".")[-1]))
    print(format_str.format("Machine Type:",          str(header.machine_type).split(".")[-1]))
    print(format_str.format("Object File Version:",   str(header.object_file_version).split(".")[-1]))
    print(format_hex.format("Entry Point:",           header.entrypoint))
    print(format_hex.format("Program Header Offset:", header.program_header_offset))
    print(format_hex.format("Section Header Offset:", header.section_header_offset))
    print(format_hex.format("Processor flags:",       header.processor_flag))
    print(format_dec.format("Header Size:",           header.header_size))
    print(format_dec.format("Program Header Size:",   header.program_header_size))
    print(format_dec.format("Number of segments:",    header.numberof_segments))
    print(format_dec.format("Number of sections:",    header.numberof_sections))
    print("")


@exceptions_handler(Exception)
def print_sections(binary):
    sections = binary.sections
    if len(sections) > 0:
        print("== Sections ==\n")
        f_title = "|{:<30} | {:<12}| {:<17}| {:<12}| {:<10}| {:<8}| {:<8}|"
        f_value = "|{:<30} | {:<12}| 0x{:<14x} | 0x{:<10x}| 0x{:<8x}| {:<8.2f}| {:<10}"
        print(f_title.format("Name", "Type", "Virtual address", "File offset", "Size", "Entropy", "Segment(s)"))

        for section in sections:
            segments_str = " - ".join([str(s.type).split(".")[-1] for s in section.segments])
            print(f_value.format(
                section.name,
                str(section.type).split(".")[-1],
                section.virtual_address,
                section.file_offset,
                section.size,
                abs(section.entropy),
                segments_str))
        print("")
    else:
        print("No sections")

@exceptions_handler(Exception)
def print_segments(binary):
    segments = binary.segments
    # Segments
    if len(segments) > 0:
        print("== Segments ==\n")
        f_title = "|{:<30} | {:<10}| {:<18}| {:<17}| {:<17}| {:<17}| {:<19}|"
        f_value = "|{:<30} | {:<10}| 0x{:<16x}| 0x{:<15x}| 0x{:<15x}| 0x{:<15x}| {}"
        print(f_title.format("Type",
            "Flag", "File offset", "Virtual Address", "Virtual Size", "Size", "Sections"))

        for segment in segments:
            sections = segment.sections
            s = ", ".join([section.name for section in sections])
            print(f_value.format(
                str(segment.type).split(".")[-1],
                segment.flag,
                segment.file_offset,
                segment.virtual_address,
                segment.virtual_size,
                segment.physical_size, s))
        print("")
    else:
        print("No segments")

@exceptions_handler(Exception)
def print_dynamic_entries(binary):
    dynamicEntries = binary.dynamic_entries
    # Dynamic entries
    if len(dynamicEntries) > 0:
        print("== Dynamic entries ==\n")
        f_title = "|{:<12} | {:<10}| {:<20}|"
        f_value = "|{:<12} | 0x{:<8x}| {:<20}|"
        print(f_title.format("Tag", "Value", "Info"))
        for dynEntry in dynamicEntries:
            if dynEntry.tag == ELF.DYNAMIC_TAGS.NULL:
                continue
            if dynEntry.tag in [ELF.DYNAMIC_TAGS.SONAME, ELF.DYNAMIC_TAGS.NEEDED, ELF.DYNAMIC_TAGS.RUNPATH, ELF.DYNAMIC_TAGS.RPATH]:
                print(f_value.format(str(dynEntry.tag).split(".")[-1], dynEntry.value, dynEntry.name))
            elif dynEntry.tag in [ELF.DYNAMIC_TAGS.INIT_ARRAY,ELF.DYNAMIC_TAGS.FINI_ARRAY]:
                print(f_value.format(str(dynEntry.tag).split(".")[-1], dynEntry.value, ", ".join(map(hex, dynEntry.array))))
            else:
                print(f_value.format(str(dynEntry.tag).split(".")[-1], dynEntry.value, ""))

        print("")

@exceptions_handler(Exception)
def print_symbols(binary):

    static_symbols       = binary.static_symbols
    dynamic_symbols      = binary.dynamic_symbols

    if len(static_symbols) > 0:
        try:
            maxsize = max([len(symbol.demangled_name) for symbol in static_symbols])
        except:
            maxsize = max([len(symbol.name) for symbol in static_symbols])
        maxsize = min(maxsize, terminal_columns - 50) if terminal_columns > 50 else terminal_columns
        f_title = "|{:<" + str(maxsize) + "} | {:<7}| {:<8}|"
        f_value = "|{:<" + str(maxsize) + "} | {:<7}| {:<8x}|"

        # Static symbols
        print("== Static symbols ==\n")
        print(f_title.format("Name", "Type", "Value", "Version"))
        for symbol in static_symbols:
            try:
                symbol_name = symbol.demangled_name
            except:
                symbol_name = symbol.name
            print(f_value.format(symbol_name, str(symbol.type).split(".")[-1], symbol.value))


    if len(dynamic_symbols) > 0:
        try:
            maxsize = max([len(symbol.demangled_name) for symbol in dynamic_symbols])
        except:
            maxsize = max([len(symbol.name) for symbol in dynamic_symbols])
        maxsize = min(maxsize, terminal_columns - 50) if terminal_columns > 50 else terminal_columns

        f_title = "|{:<" + str(maxsize) + "} | {:<7}| {:<8}|"
        f_value = "|{:<" + str(maxsize) + "} | {:<7}| {:<8x}|"

        # Dynamic symbols
        print("== Dynamic symbols ==\n")
        print(f_title.format("Name", "Type", "Value", "Version"))

        for symbol in dynamic_symbols:
            symbol_version = symbol.symbol_version if symbol.has_version else ""

            try:
                symbol_name = symbol.demangled_name
            except:
                symbol_name = symbol.name
            print(f_value.format(
                symbol_name,
                str(symbol.type).split(".")[-1],
                symbol.value,
                str(symbol_version)))

@exceptions_handler(Exception)
def print_relocations(binary):
    dynamicrelocations = binary.dynamic_relocations
    pltgot_relocations = binary.pltgot_relocations

    ## Dynamic relocations ##
    if len(dynamicrelocations) > 0:
        print("== Dynamic Relocations ==\n")
        f_title = "|{:<10} | {:<10}| {:<8}| {:<30} |"
        f_value = "|0x{:<8x} | {:<10}| {:<8d}| {:<30} |"

        print(f_title.format("Address", "Type", "Size", "Symbol"))

        for relocation in dynamicrelocations:
            type = str(relocation.type)
            if binary.header.machine_type == ELF.ARCH.x86_64:
                type = str(ELF.RELOCATION_X86_64(relocation.type))
            elif binary.header.machine_type == ELF.ARCH.i386:
                type = str(ELF.RELOCATION_i386(relocation.type))
            elif binary.header.machine_type == ELF.ARCH.ARM:
                type = str(ELF.RELOCATION_ARM(relocation.type))
            elif binary.header.machine_type == ELF.ARCH.AARCH64:
                type = str(ELF.RELOCATION_AARCH64(relocation.type))

            symbol_name = str(relocation.symbol.name) if relocation.has_symbol else ""

            print(f_value.format(
                relocation.address,
                type.split(".")[-1],
                relocation.size,
                symbol_name))


    if len(pltgot_relocations) > 0:
        print("== PLT/GOT Relocations ==\n")
        f_title = "|{:<10} | {:<10}| {:<8}| {:<30} |"
        f_value = "|0x{:<8x} | {:<10}| {:<8d}| {:<30} |"

        print(f_title.format("Address", "Type", "Size", "Symbol"))

        for relocation in pltgot_relocations:
            type = str(relocation.type)
            if binary.header.machine_type == ELF.ARCH.x86_64:
                type = str(ELF.RELOCATION_X86_64(relocation.type))
            elif binary.header.machine_type == ELF.ARCH.i386:
                type = str(ELF.RELOCATION_i386(relocation.type))
            elif binary.header.machine_type == ELF.ARCH.ARM:
                type = str(ELF.RELOCATION_ARM(relocation.type))
            elif binary.header.machine_type == ELF.ARCH.AARCH64:
                type = str(ELF.RELOCATION_AARCH64(relocation.type))

            symbol_name = str(relocation.symbol.name) if relocation.has_symbol else ""
            print(f_value.format(
                relocation.address,
                type.split(".")[-1],
                relocation.size,
                symbol_name))

@exceptions_handler(Exception)
def print_exported_symbols(binary):
    symbols = binary.exported_symbols
    f_title = "|{:<30} | {:<7}| {:<8}| {:<15}|"
    f_value = "|{:<30} | {:<7}| {:<8x}| {:<15}|"
    print("== Exported symbols ==\n")
    print(f_title.format("Name", "Type", "Value", "Version"))

    for symbol in symbols:
        symbol_version = symbol.symbol_version if symbol.has_version else ""

        print(f_value.format(
            str(symbol.name),
            str(symbol.type).split(".")[-1],
            symbol.value,
            str(symbol_version)))

@exceptions_handler(Exception)
def print_imported_symbols(binary):
    symbols = binary.imported_symbols
    f_title = "|{:<30} | {:<7}| {:<8}| {:<15}|"
    f_value = "|{:<30} | {:<7}| {:<8x}| {:<15}|"
    print("== Imported symbols ==\n")
    print(f_title.format("Name", "Type", "Value", "Version"))

    for symbol in symbols:
        symbol_version = symbol.symbol_version if symbol.has_version else ""

        print(f_value.format(
            str(symbol.name),
            str(symbol.type).split(".")[-1],
            symbol.value,
            str(symbol_version)))

@exceptions_handler(Exception)
def print_information(binary):
    print("== Information ==\n")
    format_str = "{:<30} {:<30}"
    format_hex = "{:<30} 0x{:<28x}"
    format_dec = "{:<30} {:<30d}"
    print(format_str.format("Name:",         binary.name))
    print(format_hex.format("Address base:", binary.imagebase))
    print(format_hex.format("Virtual size:", binary.virtual_size))

@exceptions_handler(Exception)
def print_gnu_hash(binary):
    print("== GNU Hash ==\n")

    if not binary.use_gnu_hash:
        return

    gnu_hash = binary.gnu_hash

    format_str = "{:<30} {}"
    format_hex = "{:<30} 0x{:<28x}"
    format_dec = "{:<30} {:<30d}"

    print(format_dec.format("Number of buckets:",  gnu_hash.nb_buckets))
    print(format_dec.format("First symbol index:", gnu_hash.symbol_index))
    print(format_hex.format("Shift Count:",        gnu_hash.shift2))
    print(format_str.format("Bloom filters:",      gnu_hash.bloom_filters))
    print(format_str.format("Buckets:",            gnu_hash.buckets))
    print(format_str.format("Hash values:",        gnu_hash.hash_values))


@exceptions_handler(Exception)
def print_sysv_hash(binary):
    print("== SYSV Hash ==\n")

    if not binary.use_sysv_hash:
        return

    sysv_hash = binary.sysv_hash

    format_str = "{:<30} {}"
    format_hex = "{:<30} 0x{:<28x}"
    format_dec = "{:<30} {:<30d}"

    print(format_dec.format("Number of buckets:", sysv_hash.nbucket))
    print(format_dec.format("Number of chains:",  sysv_hash.nchain))
    print(format_str.format("Buckets:",           sysv_hash.buckets))
    print(format_str.format("Chains:",            sysv_hash.chains))


@exceptions_handler(Exception)
def print_notes(binary):
    print("== Notes ==\n")

    format_str = "{:<19} {}"
    format_hex = "{:<19} 0x{:<28x}"
    format_dec = "{:<19} {:<30d}"

    notes = binary.notes
    for idx, note in enumerate(notes):
        description = note.description
        description_str = " ".join(map(lambda e : "{:02x}".format(e), description[:16]))
        if len(description) > 16:
            description_str += " ..."

        print("Note #{:d}".format(idx))

        print(format_str.format("Name:",        note.name))
        print(format_str.format("Type:",        str(ELF.NOTE_TYPES(note.type)).split(".")[-1]))
        print(format_str.format("Description:", description_str))

        if ELF.NOTE_TYPES(note.type) == ELF.NOTE_TYPES.ABI_TAG:
            try:
                version = note.version
                version_str = "{:d}.{:d}.{:d}".format(version[0], version[1], version[2])

                print(format_str.format("ABI:",     note.abi))
                print(format_str.format("Version:", version_str))
            except lief.corrupted:
                pass

        if ELF.NOTE_TYPES(note.type) == ELF.NOTE_TYPES.GOLD_VERSION:
            print(format_str.format("Version:", "".join(map(chr, note.description))))


        print("\n")


def main():
    optparser = OptionParser(
            usage='Usage: %prog [options] <elf-file>',
            add_help_option=False, # -h is a real option of readelf
            prog=sys.argv[0])

    optparser.add_option('-a', '--all',
            action='store_true', dest='show_all',
            help='Equivalent to: -h -l -S -s -r -d -V')

    optparser.add_option('-d', '--dynamic',
            action='store_true', dest='show_dynamic_tags',
            help='Display the dynamic section')

    optparser.add_option('-H', '--help',
            action='store_true', dest='help',
            help='Display this information')

    optparser.add_option('-h', '--file-header',
            action='store_true', dest='show_file_header',
            help='Display the ELF file header')

    optparser.add_option('-i', '--imported',
            action='store_true', dest='show_imported_symbols',
            help='Display imported symbols')

    optparser.add_option('-l', '--program-headers', '--segments',
            action='store_true', dest='show_program_header',
            help='Display the program headers')

    optparser.add_option('-S', '--section-headers', '--sections',
            action='store_true', dest='show_section_header',
            help="Display the sections' headers")

    optparser.add_option('-e', '--headers',
            action='store_true', dest='show_all_headers',
            help='Equivalent to: -h -l -S')

    optparser.add_option('-s', '--symbols', '--syms',
            action='store_true', dest='show_symbols',
            help='Display the symbol table')

    optparser.add_option('-r', '--relocs',
            action='store_true', dest='show_relocs',
            help='Display the relocations (if present)')

    optparser.add_option('-V', '--version-info',
            action='store_true', dest='show_version_info',
            help='Display the version sections (if present)')

    optparser.add_option('-x', '--exported',
            action='store_true', dest='show_exported_symbols',
            help='Display exported symbols')

    optparser.add_option('--gnu-hash',
            action='store_true', dest='show_gnu_hash',
            help='Display GNU Hash')

    optparser.add_option('--sysv-hash',
            action='store_true', dest='show_sysv_hash',
            help='Display SYSV Hash')

    optparser.add_option('-n', '--notes',
            action='store_true', dest='show_notes',
            help='Display Notes')


    options, args = optparser.parse_args()

    if options.help or len(args) == 0:
        optparser.print_help()
        sys.exit(0)


    binary = ELF.parse(args[0])
    print_information(binary)
    if options.show_all:
        do_file_header = do_section_header = do_program_header = True

    if options.show_all_headers:
        do_file_header = do_section_header = do_program_header = True
    else:
        do_file_header    = options.show_file_header
        do_section_header = options.show_section_header
        do_program_header = options.show_program_header

    if do_file_header or options.show_all:
        print_header(binary)

    if do_section_header or options.show_all:
        print_sections(binary)

    if do_program_header or options.show_all:
        print_segments(binary)

    if options.show_dynamic_tags or options.show_all:
        print_dynamic_entries(binary)

    if options.show_symbols or options.show_all:
        print_symbols(binary)

    if options.show_relocs or options.show_all:
        print_relocations(binary)

    if options.show_imported_symbols or options.show_all:
        print_imported_symbols(binary)

    if options.show_exported_symbols or options.show_all:
        print_exported_symbols(binary)

    if options.show_gnu_hash or options.show_all:
        print_gnu_hash(binary)

    if options.show_sysv_hash or options.show_all:
        print_sysv_hash(binary)

    if options.show_notes or options.show_all:
        print_notes(binary)




if __name__ == "__main__":
    main()






