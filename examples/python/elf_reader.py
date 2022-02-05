#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Description
# -----------
# Print information about an ELF binary

import os
import sys
import textwrap
import traceback

import lief
from lief import ELF
import argparse

terminal_rows, terminal_columns = 100, 110
try:
    terminal_rows, terminal_columns = os.popen('stty size', 'r').read().split()
except ValueError:
    pass

terminal_columns = int(terminal_columns) - 10
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
    format_hex = "{:<30} 0x{:<13x}"
    format_dec = "{:<30} {:<30d}"
    format_ide = "{:<30} {:<02x} {:<02x} {:<02x} {:<02x}"

    eflags_str = ""
    if header.machine_type == lief.ELF.ARCH.ARM:
        eflags_str = " - ".join([str(s).split(".")[-1] for s in header.arm_flags_list])

    if header.machine_type in [lief.ELF.ARCH.MIPS, lief.ELF.ARCH.MIPS_RS3_LE, lief.ELF.ARCH.MIPS_X]:
        eflags_str = " - ".join([str(s).split(".")[-1] for s in header.mips_flags_list])

    if header.machine_type == lief.ELF.ARCH.PPC64:
        eflags_str = " - ".join([str(s).split(".")[-1] for s in header.ppc64_flags_list])

    if header.machine_type == lief.ELF.ARCH.HEXAGON:
        eflags_str = " - ".join([str(s).split(".")[-1] for s in header.hexagon_flags_list])
    print(identity)
    print(format_ide.format("Magic:",                 identity[0], identity[1], identity[2], identity[3]))
    print(format_str.format("Class:",                 str(header.identity_class).split(".")[-1]))
    print(format_str.format("Endianness:",            str(header.identity_data).split(".")[-1]))
    print(format_str.format("Version:",               str(header.identity_version).split(".")[-1]))
    print(format_str.format("OS/ABI:",                str(header.identity_os_abi).split(".")[-1]))
    print(format_dec.format("ABI Version:",           header.identity_abi_version))
    print(format_str.format("File Type:",             str(header.file_type).split(".")[-1]))
    print(format_str.format("Machine Type:",          str(header.machine_type).split(".")[-1]))
    print(format_str.format("Object File Version:",   str(header.object_file_version).split(".")[-1]))
    print(format_hex.format("Entry Point:",           header.entrypoint))
    print(format_hex.format("Program Header Offset:", header.program_header_offset))
    print(format_hex.format("Section Header Offset:", header.section_header_offset))
    print(format_hex.format("Processor flags:",       header.processor_flag) + eflags_str)
    print(format_dec.format("Header Size:",           header.header_size))
    print(format_dec.format("Program Header Size:",   header.program_header_size))
    print(format_dec.format("Section Header Size:",   header.section_header_size))
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
            "Flags", "File offset", "Virtual Address", "Virtual Size", "Size", "Sections"))

        for segment in segments:
            sections = segment.sections
            s = ", ".join([section.name for section in sections])
            flags_str = ["-"] * 3
            if ELF.SEGMENT_FLAGS.R in segment:
                flags_str[0] = "r"

            if ELF.SEGMENT_FLAGS.W in segment:
                flags_str[1] = "w"

            if ELF.SEGMENT_FLAGS.X in segment:
                flags_str[2] = "x"
            flags_str = "".join(flags_str)

            print(f_value.format(
                str(segment.type).split(".")[-1],
                flags_str,
                segment.file_offset,
                segment.virtual_address,
                segment.virtual_size,
                segment.physical_size, s))
        print("")
    else:
        print("No segments")

@exceptions_handler(Exception)
def print_dynamic_entries(binary):
    dynamic_entries = binary.dynamic_entries
    # Dynamic entries
    if len(dynamic_entries) == 0:
        return

    print("== Dynamic entries ==\n")
    f_title = "|{:<16} | {:<10}| {:<20}|"
    f_value = "|{:<16} | 0x{:<8x}| {:<20}|"
    print(f_title.format("Tag", "Value", "Info"))
    for entry in dynamic_entries:
        if entry.tag == ELF.DYNAMIC_TAGS.NULL:
            continue

        if entry.tag in [ELF.DYNAMIC_TAGS.SONAME, ELF.DYNAMIC_TAGS.NEEDED, ELF.DYNAMIC_TAGS.RUNPATH, ELF.DYNAMIC_TAGS.RPATH]:
            print(f_value.format(str(entry.tag).split(".")[-1], entry.value, entry.name))
        elif type(entry) is ELF.DynamicEntryArray: # [ELF.DYNAMIC_TAGS.INIT_ARRAY,ELF.DYNAMIC_TAGS.FINI_ARRAY]:
            print(f_value.format(str(entry.tag).split(".")[-1], entry.value, ", ".join(map(hex, entry.array))))
        elif entry.tag == ELF.DYNAMIC_TAGS.FLAGS:
            flags_str = " - ".join([str(ELF.DYNAMIC_FLAGS(s)).split(".")[-1] for s in entry.flags])
            print(f_value.format(str(entry.tag).split(".")[-1], entry.value, flags_str))
        elif entry.tag == ELF.DYNAMIC_TAGS.FLAGS_1:
            flags_str = " - ".join([str(ELF.DYNAMIC_FLAGS_1(s)).split(".")[-1] for s in entry.flags])
            print(f_value.format(str(entry.tag).split(".")[-1], entry.value, flags_str))
        else:
            print(f_value.format(str(entry.tag).split(".")[-1], entry.value, ""))

    print("")


@exceptions_handler(Exception)
def print_symbols(symbols, no_trunc):
    can_demangle = len(symbols) > 0 and len(symbols[0].demangled_name) > 0
    if can_demangle:
        maxsize = max([len(symbol.demangled_name) for symbol in symbols])
    else:
        maxsize = max([len(symbol.name) for symbol in symbols])

    SIZE = 70
    maxsize = min(maxsize, terminal_columns - SIZE) if terminal_columns > SIZE else terminal_columns

    f_title = "|{:<" + str(maxsize) + "} | {:<7}| {:<8}| {:<10}| {:<8}| {:<4}| {:<14}|"
    f_value = "|{:<" + str(maxsize) + "} | {:<7}| {:<8x}| {:<10}| {:<8}| {:<4}| {:<14}|"

    print(f_title.format("Name", "Type", "Value", "Visibility", "Binding", "I/E", "Version"))

    for symbol in symbols:
        symbol_version = symbol.symbol_version if symbol.has_version else ""

        import_export = ""
        if symbol.imported:
            import_export = "I"

        if symbol.exported:
            import_export = "E"

        symbol_name = symbol.demangled_name
        if len(symbol_name) == 0:
            symbol_name = symbol.name

        wrapped = textwrap.wrap(symbol_name, maxsize)

        if len(wrapped) <= 1 or no_trunc:
            symbol_name = symbol_name
        else:
            symbol_name = wrapped[0][:-3] + "..."

        print(f_value.format(
            symbol_name,
            str(symbol.type).split(".")[-1],
            symbol.value,
            str(symbol.visibility).split(".")[-1],
            str(symbol.binding).split(".")[-1],
            import_export,
            str(symbol_version)
            ))

@exceptions_handler(Exception)
def print_dynamic_symbols(binary, args):
    print("== Dynamic symbols ==\n")
    print_symbols(binary.dynamic_symbols, args.no_trunc)


@exceptions_handler(Exception)
def print_static_symbols(binary, args):
    print("== Static symbols ==\n")
    print_symbols(binary.static_symbols, args.no_trunc)

@exceptions_handler(Exception)
def print_relocations(binary, relocations):
    f_title = "|{:<10} | {:<10}| {:<8}| {:<8}| {:<8}| {:<15}| {:<30} |"
    f_value = "|0x{:<8x} | {:<10}| {:<8d}| {:<8d}| {:<8x}| {:<15}| {:<30} |"

    print(f_title.format("Address", "Type", "Info", "Size", "Addend", "Purpose", "Symbol"))

    for relocation in relocations:
        type = str(relocation.type)
        if binary.header.machine_type == ELF.ARCH.x86_64:
            type = str(ELF.RELOCATION_X86_64(relocation.type))
        elif binary.header.machine_type == ELF.ARCH.i386:
            type = str(ELF.RELOCATION_i386(relocation.type))
        elif binary.header.machine_type == ELF.ARCH.ARM:
            type = str(ELF.RELOCATION_ARM(relocation.type))
        elif binary.header.machine_type == ELF.ARCH.AARCH64:
            type = str(ELF.RELOCATION_AARCH64(relocation.type))

        symbol_name = ""
        if relocation.has_symbol:
            symbol: lief.ELF.Symbol = relocation.symbol
            if len(symbol.name) > 0:
                symbol_name = symbol.name
            elif symbol.type == lief.ELF.SYMBOL_TYPES.SECTION:
                shndx = symbol.shndx
                sections = binary.sections
                if 0 < shndx and shndx < len(sections):
                    symbol_name = sections[shndx].name + " + " + hex(relocation.addend)
                else:
                    symbol_name = "<section #{}>".format(shndx)


        print(f_value.format(
            relocation.address,
            type.split(".")[-1],
            relocation.info,
            relocation.size,
            relocation.addend,
            str(relocation.purpose).split(".")[-1],
            symbol_name))


@exceptions_handler(Exception)
def print_all_relocations(binary):
    dynamicrelocations = binary.dynamic_relocations
    pltgot_relocations = binary.pltgot_relocations
    object_relocations = binary.object_relocations

    if len(dynamicrelocations) > 0:
        print("== Dynamic Relocations ==\n")
        print_relocations(binary, dynamicrelocations)


    if len(pltgot_relocations) > 0:
        print("== PLT/GOT Relocations ==\n")
        print_relocations(binary, pltgot_relocations)

    if len(object_relocations) > 0:
        print("== Object Relocations ==\n")
        print_relocations(binary, object_relocations)

@exceptions_handler(Exception)
def print_exported_symbols(binary, args):
    symbols = binary.exported_symbols

    print("== Exported symbols ==\n")
    if len(symbols) == 0:
        print("No exports!")
        return
    print_symbols(symbols, args.no_trunc)

@exceptions_handler(Exception)
def print_imported_symbols(binary, args):
    symbols = binary.imported_symbols
    print("== Imported symbols ==\n")

    if len(symbols) == 0:
        print("No imports!")
        return
    print_symbols(symbols, args.no_trunc)

@exceptions_handler(Exception)
def print_information(binary):
    print("== Information ==\n")
    format_str = "{:<30} {:<30}"
    format_hex = "{:<30} 0x{:<28x}"
    format_dec = "{:<30} {:<30d}"
    print(format_str.format("Name:",         binary.name))
    print(format_hex.format("Address base:", binary.imagebase))
    print(format_hex.format("Virtual size:", binary.virtual_size))
    print(format_str.format("PIE:",          str(binary.is_pie)))
    print(format_str.format("NX:",           str(binary.has_nx)))

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

        type_str = note.type_core if note.is_core else note.type
        type_str = str(type_str).split(".")[-1]

        print(format_str.format("Name:",        note.name))
        print(format_str.format("Type:",        type_str))
        print(format_str.format("Description:", description_str))

        note_details = note.details

        if type(note_details) == lief.ELF.AndroidNote:
            print(format_dec.format("SDK Version:",      note_details.sdk_version))
            print(format_str.format("NDK Version:",      note_details.ndk_version))
            print(format_str.format("NDK build number:", note_details.ndk_build_number))

        if type(note_details) == lief.ELF.NoteAbi:
            version     = note_details.version
            version_str = "{:d}.{:d}.{:d}".format(version[0], version[1], version[2])

            print(format_str.format("ABI:",     note_details.abi))
            print(format_str.format("Version:", version_str))

        if ELF.NOTE_TYPES(note.type) == ELF.NOTE_TYPES.GOLD_VERSION:
            print(format_str.format("Version:", "".join(map(chr, note.description))))

        if note.is_core:
            print(note_details)


        print("\n")


@exceptions_handler(Exception)
def print_ctor(binary):
    print("== Constructors ==\n")

    print("Functions: ({:d})".format(len(binary.ctor_functions)))
    for idx, f in enumerate(binary.ctor_functions):
        print("    [{:d}] {}: 0x{:x}".format(idx, f.name, f.address))

@exceptions_handler(Exception)
def print_strings(binary):
    print("== Strings ==\n")


    strings = binary.strings
    print("Strings: ({:d})".format(len(binary.strings)))
    for s in strings:
        print("    {}".format(s))


@exceptions_handler(Exception)
def print_functions(binary):
    print("== Functions ==\n")

    functions = binary.functions
    print("Functions: ({:d})".format(len(functions)))
    for idx, f in enumerate(functions):
        print("    [{:d}] {}: 0x{:x}".format(idx, f.name, f.address))


def main():
    parser = argparse.ArgumentParser(add_help=False, prog=sys.argv[0])
    parser.add_argument("elf_file")

    parser.add_argument('-a', '--all',
            action='store_true', dest='show_all',
            help='Equivalent to: -h -l -S -s -r -d -V')

    parser.add_argument('-d', '--dynamic',
            action='store_true', dest='show_dynamic_tags',
            help='Display the dynamic section')

    parser.add_argument('-H', '--help',
            action='help', dest='help',
            help='Display this information')

    parser.add_argument('-h', '--file-header',
            action='store_true', dest='show_file_header',
            help='Display the ELF file header')

    parser.add_argument('-i', '--imported',
            action='store_true', dest='show_imported_symbols',
            help='Display imported symbols')

    parser.add_argument('-l', '--program-headers', '--segments',
            action='store_true', dest='show_program_header',
            help='Display the program headers')

    parser.add_argument('-S', '--section-headers', '--sections',
            action='store_true', dest='show_section_header',
            help="Display the sections' headers")

    parser.add_argument('-e', '--headers',
            action='store_true', dest='show_all_headers',
            help='Equivalent to: -h -l -S')

    parser.add_argument('-s', '--symbols', '--syms',
            action='store_true', dest='show_symbols',
            help='Display the symbol table')

    parser.add_argument('--dynamic-symbols', '--dsyms',
            action='store_true', dest='show_dynamic_symbols',
            help='Display the dynamic symbols')

    parser.add_argument('--static-symbols', '--ssyms',
            action='store_true', dest='show_static_symbols',
            help='Display the static symbols')

    parser.add_argument('-r', '--relocs',
            action='store_true', dest='show_relocs',
            help='Display the relocations (if present)')

    parser.add_argument('-V', '--version-info',
            action='store_true', dest='show_version_info',
            help='Display the version sections (if present)')

    parser.add_argument('-x', '--exported',
            action='store_true', dest='show_exported_symbols',
            help='Display exported symbols')

    parser.add_argument('--gnu-hash',
            action='store_true', dest='show_gnu_hash',
            help='Display GNU Hash')

    parser.add_argument('--sysv-hash',
            action='store_true', dest='show_sysv_hash',
            help='Display SYSV Hash')

    parser.add_argument('-n', '--notes',
            action='store_true', dest='show_notes',
            help='Display Notes')

    parser.add_argument('--no-trunc',
            action='store_true', dest='no_trunc',
            default=False,
            help='Do not trunc symbol names ...')

    parser.add_argument('--ctor',
            action='store_true', dest='show_ctor',
            help='Constructor functions')

    parser.add_argument('--strings',
            action='store_true', dest='show_strings',
            help='Strings present in the current ELF')

    parser.add_argument('--functions',
            action='store_true', dest='show_functions',
            help='List all function addresses found')

    # Logging setup
    logger_group = parser.add_argument_group('Logger')
    verbosity = logger_group.add_mutually_exclusive_group()

    verbosity.add_argument('--debug',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LOGGING_LEVEL.DEBUG)

    verbosity.add_argument('--trace',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LOGGING_LEVEL.TRACE)

    verbosity.add_argument('--info',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LOGGING_LEVEL.INFO)

    verbosity.add_argument('--warn',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LOGGING_LEVEL.WARNING)

    verbosity.add_argument('--err',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LOGGING_LEVEL.ERROR)

    verbosity.add_argument('--critical',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LOGGING_LEVEL.CRITICAL)

    parser.set_defaults(main_verbosity=lief.logging.LOGGING_LEVEL.WARNING)

    args = parser.parse_args()

    lief.logging.set_level(args.main_verbosity)
    binary = ELF.parse(args.elf_file)
    print_information(binary)
    if args.show_all:
        do_file_header = do_section_header = do_program_header = True

    if args.show_all_headers:
        do_file_header = do_section_header = do_program_header = True
    else:
        do_file_header    = args.show_file_header
        do_section_header = args.show_section_header
        do_program_header = args.show_program_header

    if do_file_header or args.show_all:
        print_header(binary)

    if do_section_header or args.show_all:
        print_sections(binary)

    if do_program_header or args.show_all:
        print_segments(binary)

    if args.show_dynamic_tags or args.show_all:
        print_dynamic_entries(binary)

    if (args.show_symbols or args.show_all or args.show_dynamic_symbols) and len(binary.dynamic_symbols) > 0:
        print_dynamic_symbols(binary, args)

    if (args.show_symbols or args.show_all or args.show_static_symbols) and len(binary.static_symbols) > 0:
        print_static_symbols(binary, args)

    if args.show_relocs or args.show_all:
        print_all_relocations(binary)

    if args.show_imported_symbols or args.show_all:
        print_imported_symbols(binary, args)

    if args.show_exported_symbols or args.show_all:
        print_exported_symbols(binary, args)

    if (args.show_gnu_hash or args.show_all) and binary.use_gnu_hash:
        print_gnu_hash(binary)

    if (args.show_sysv_hash or args.show_all) and binary.use_sysv_hash:
        print_sysv_hash(binary)

    if args.show_notes or args.show_all:
        print_notes(binary)

    if args.show_ctor or args.show_all:
        print_ctor(binary)

    if args.show_strings or args.show_all:
        print_strings(binary)

    if args.show_functions:
        print_functions(binary)




if __name__ == "__main__":
    main()
