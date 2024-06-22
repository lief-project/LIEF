#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Description
# -----------
# Print information about a PE file

import lief
from lief import PE
from lief.PE import oid_to_string

import argparse
import sys
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
def print_information(binary):
    print("== Information ==\n")
    format_str = "{:<30} {:<30}"
    format_hex = "{:<30} 0x{:<28x}"
    print(format_hex.format("Virtual size:", binary.virtual_size))
    print(format_str.format("Imphash:",      PE.get_imphash(binary)))
    print(format_str.format("PIE:",          str(binary.is_pie)))
    print(format_str.format("NX:",           str(binary.has_nx)))

@exceptions_handler(Exception)
def print_header(binary):
    dos_header       = binary.dos_header
    header           = binary.header
    optional_header  = binary.optional_header

    format_str = "{:<33} {:<30}"
    format_hex = "{:<33} 0x{:<28x}"
    format_dec = "{:<33} {:<30d}"

    print("== Dos Header ==")
    print(format_str.format("Magic:",                       str((dos_header.magic))))
    print(format_dec.format("Used bytes in the last page:", dos_header.used_bytes_in_last_page))
    print(format_dec.format("File size in pages:",          dos_header.file_size_in_pages))
    print(format_dec.format("Number of relocations:",       dos_header.numberof_relocation))
    print(format_dec.format("Header size in paragraphs:",   dos_header.header_size_in_paragraphs))
    print(format_dec.format("Minimum extra paragraphs:",    dos_header.minimum_extra_paragraphs))
    print(format_dec.format("Maximum extra paragraphs",     dos_header.maximum_extra_paragraphs))
    print(format_dec.format("Initial relative SS",          dos_header.initial_relative_ss))
    print(format_hex.format("Initial SP:",                  dos_header.initial_sp))
    print(format_hex.format("Checksum:",                    dos_header.checksum))
    print(format_dec.format("Initial IP:",                  dos_header.initial_ip))
    print(format_dec.format("Initial CS:",                  dos_header.initial_relative_cs))
    print(format_hex.format("Address of relocation table:", dos_header.addressof_relocation_table))
    print(format_dec.format("Overlay number:",              dos_header.overlay_number))
    print(format_dec.format("OEM ID:",                      dos_header.oem_id))
    print(format_dec.format("OEM information",              dos_header.oem_info))
    print(format_hex.format("Address of optional header:",  dos_header.addressof_new_exeheader))
    print("")

    print("== Header ==")

    char_str = " - ".join([str(chara).split(".")[-1] for chara in header.characteristics_list])

    print(format_str.format("Signature:",               "".join(map(chr, header.signature))))
    print(format_str.format("Machine:",                 str(header.machine)))
    print(format_dec.format("Number of sections:",      header.numberof_sections))
    print(format_dec.format("Time Date stamp:",         header.time_date_stamps))
    print(format_dec.format("Pointer to symbols:",      header.pointerto_symbol_table))
    print(format_dec.format("Number of symbols:",       header.numberof_symbols))
    print(format_dec.format("Size of optional header:", header.sizeof_optional_header))
    print(format_str.format("Characteristics:",         char_str))
    print("")


    dll_char_str = " - ".join([str(chara).split(".")[-1] for chara in optional_header.dll_characteristics_lists])
    subsystem_str = str(optional_header.subsystem).split(".")[-1]
    print("== Optional Header ==")
    magic = "PE32" if optional_header.magic == PE.PE_TYPE.PE32 else "PE64"
    print(format_str.format("Magic:", magic))
    print(format_dec.format("Major linker version:",           optional_header.major_linker_version))
    print(format_dec.format("Minor linker version:",           optional_header.minor_linker_version))
    print(format_dec.format("Size of code:",                   optional_header.sizeof_code))
    print(format_dec.format("Size of initialized data:",       optional_header.sizeof_initialized_data))
    print(format_dec.format("Size of uninitialized data:",     optional_header.sizeof_uninitialized_data))
    print(format_hex.format("Entry point:",                    optional_header.addressof_entrypoint))
    print(format_hex.format("Base of code:",                   optional_header.baseof_code))
    if magic == "PE32":
        print(format_hex.format("Base of data",                optional_header.baseof_data))
    print(format_hex.format("Image base:",                     optional_header.imagebase))
    print(format_hex.format("Section alignment:",              optional_header.section_alignment))
    print(format_hex.format("File alignment:",                 optional_header.file_alignment))
    print(format_dec.format("Major operating system version:", optional_header.major_operating_system_version))
    print(format_dec.format("Minor operating system version:", optional_header.minor_operating_system_version))
    print(format_dec.format("Major image version:",            optional_header.major_image_version))
    print(format_dec.format("Minor image version:",            optional_header.minor_image_version))
    print(format_dec.format("Major subsystem version:",        optional_header.major_subsystem_version))
    print(format_dec.format("Minor subsystem version:",        optional_header.minor_subsystem_version))
    print(format_dec.format("WIN32 version value:",            optional_header.win32_version_value))
    print(format_hex.format("Size of image:",                  optional_header.sizeof_image))
    print(format_hex.format("Size of headers:",                optional_header.sizeof_headers))
    print(format_hex.format("Checksum:",                       optional_header.checksum))
    print(format_str.format("Subsystem:",                      subsystem_str))
    print(format_str.format("DLL Characteristics:",            dll_char_str))
    print(format_hex.format("Size of stack reserve:",          optional_header.sizeof_stack_reserve))
    print(format_hex.format("Size of stack commit:",           optional_header.sizeof_stack_commit))
    print(format_hex.format("Size of heap reserve:",           optional_header.sizeof_heap_reserve))
    print(format_hex.format("Size of heap commit:",            optional_header.sizeof_heap_commit))
    print(format_dec.format("Loader flags:",                   optional_header.loader_flags))
    print(format_dec.format("Number of RVA and size:",         optional_header.numberof_rva_and_size))
    print("")

@exceptions_handler(Exception)
def print_data_directories(binary):
    data_directories = binary.data_directories

    print("== Data Directories ==")
    f_title = "|{:<24} | {:<10} | {:<10} | {:<8} |"
    f_value = "|{:<24} | 0x{:<8x} | 0x{:<8x} | {:<8} |"
    print(f_title.format("Type", "RVA", "Size", "Section"))

    for directory in data_directories:
        section_name = directory.section.name if directory.has_section else ""
        print(f_value.format(str(directory.type).split('.')[-1], directory.rva, directory.size, section_name))
    print("")


@exceptions_handler(Exception)
def print_sections(binary):
    sections = binary.sections

    print("== Sections  ==")
    f_title = "|{:<10} | {:<16} | {:<16} | {:<18} | {:<16} | {:<9} | {:<9}"
    f_value = "|{:<10} | 0x{:<14x} | 0x{:<14x} | 0x{:<16x} | 0x{:<14x} | {:<9.2f} | {:<9}"
    print(f_title.format("Name", "Offset", "Size", "Virtual Address", "Virtual size", "Entropy", "Flags"))

    for section in sections:
        flags = ""
        for flag in section.characteristics_lists:
            flags += str(flag).split(".")[-1] + " "
        print(f_value.format(section.name, section.offset, section.size, section.virtual_address, section.virtual_size, section.entropy, flags))
    print("")


@exceptions_handler(Exception)
def print_symbols(binary):
    symbols = binary.symbols
    if len(symbols) > 0:
        print("== Symbols ==")
        f_title = "|{:<20} | {:<10} | {:<8} | {:<8} | {:<8} | {:<13} |"
        f_value = u"|{:<20} | 0x{:<8x} | {:<14} | {:<10} | {:<12} | {:<13} |"

        print(f_title.format("Name", "Value", "Section number", "Basic type", "Complex type", "Storage class"))
        for symbol in symbols:
            section_nb_str = ""
            if symbol.section_number <= 0:
                section_nb_str = str(PE.SYMBOL_SECTION_NUMBER(symbol.section_number)).split(".")[-1]
            else:
                try:
                    section_nb_str = symbol.section.name
                except Exception:
                    section_nb_str = "section<{:d}>".format(symbol.section_number)


            print(f_value.format(
                symbol.name[:20],
                symbol.value,
                section_nb_str,
                str(symbol.base_type).split(".")[-1],
                str(symbol.complex_type).split(".")[-1],
                str(symbol.storage_class).split(".")[-1]))

@exceptions_handler(Exception)
def print_imports(binary, resolve=False):
    print("== Imports ==")
    imports = binary.imports

    for import_ in imports:
        if resolve:
            import_ = lief.PE.resolve_ordinals(import_)

        print(import_.name)
        entries = import_.entries
        f_value = "  {:<33} 0x{:<14x} 0x{:<14x} 0x{:<16x}"
        for entry in entries:
            print(f_value.format(entry.name, entry.data, entry.iat_value, entry.hint))
    print("")

@exceptions_handler(Exception)
def print_tls(binary):
    format_str = "{:<33} {:<30}"
    format_hex = "{:<33} 0x{:<28x}"

    print("== TLS ==")
    tls = binary.tls
    callbacks = tls.callbacks
    print(format_hex.format("Address of callbacks:", tls.addressof_callbacks))
    if len(callbacks) > 0:
        print("Callbacks:")
        for callback in callbacks:
            print("  " + hex(callback))

    print(format_hex.format("Address of index:",  tls.addressof_index))
    print(format_hex.format("Size of zero fill:", tls.sizeof_zero_fill))
    print("{:<33} 0x{:<10x} 0x{:<10x}".format("Address of raw data:",
        tls.addressof_raw_data[0], tls.addressof_raw_data[1]))
    print(format_hex.format("Size of raw data:",  len(tls.data_template)))
    print(format_hex.format("Characteristics:",   tls.characteristics))
    print(format_str.format("Section:",           tls.section.name))
    print(format_str.format("Data directory:",    str(tls.directory.type)))
    print("")

@exceptions_handler(Exception)
def print_relocations(binary):
    relocations = binary.relocations
    print("== Relocations ==")
    for relocation in relocations:
        entries = relocation.entries
        print(hex(relocation.virtual_address))
        for entry in entries:
            print("  0x{:<8x} {:<8}".format(entry.position, str(entry.type).split(".")[-1]))
    print("")

@exceptions_handler(Exception)
def print_export(binary):
    print("== Exports ==")
    exports = binary.get_export()
    entries = exports.entries
    f_value = "{:<20} 0x{:<10x} 0x{:<10x} 0x{:<6x} 0x{:<6x} 0x{:<10x}"
    print(f_value.format(exports.name, exports.export_flags, exports.timestamp, exports.major_version, exports.minor_version, exports.ordinal_base))
    entries = sorted(entries, key=lambda e : e.ordinal)
    for entry in entries:
        extern = "[EXTERN]" if entry.is_extern else ""
        print("  {:<20} {:d} 0x{:<10x} {:<13}".format(entry.name[:20], entry.ordinal, entry.address, extern))
    print("")


@exceptions_handler(Exception)
def print_debug(binary):
    format_str = "{:<33} {:<30}"
    format_hex = "{:<33} 0x{:<28x}"
    format_dec = "{:<33} {:<30d}"

    debugs = binary.debug
    print("== Debug ({}) ==".format(len(debugs)))
    for debug in debugs:
        print(format_hex.format("Characteristics:",     debug.characteristics))
        print(format_hex.format("Timestamp:",           debug.timestamp))
        print(format_dec.format("Major version:",       debug.major_version))
        print(format_dec.format("Minor version:",       debug.minor_version))
        print(format_str.format("type:",                str(debug.type).split(".")[-1]))
        print(format_hex.format("Size of data:",        debug.sizeof_data))
        print(format_hex.format("Address of raw data:", debug.addressof_rawdata))
        print(format_hex.format("Pointer to raw data:", debug.pointerto_rawdata))

        if isinstance(debug, lief.PE.CodeViewPDB):
            code_view: lief.PE.CodeViewPDB = debug
            cv_signature = code_view.cv_signature
            sig_str = " ".join(map(lambda e : "{:02x}".format(e), code_view.signature))
            print(format_str.format("Code View Signature:", str(cv_signature).split(".")[-1]))
            print(format_str.format("Signature:", sig_str))
            print(format_dec.format("Age:", code_view.age))
            print(format_str.format("Filename:", code_view.filename))
        elif isinstance(debug, lief.PE.CodeView):
            code_view: lief.PE.CodeView = debug
            cv_signature = code_view.cv_signature
            print(format_str.format("Code View Signature:", str(cv_signature).split(".")[-1]))
        elif isinstance(debug, lief.PE.Pogo):
            pogo: lief.PE.Pogo = debug
            sig_str = str(pogo.signature).split(".")[-1]
            print(format_str.format("Signature:", sig_str))
            print("Entries:")
            for entry in pogo.entries:
                print("    {:<20} 0x{:x} ({:d})".format(entry.name, entry.start_rva, entry.size))

        print("\n")

@exceptions_handler(Exception)
def print_signature(binary):
    format_str = "{:<33} {:<30}"
    format_dec = "{:<33} {:<30d}"
    for signature in binary.signatures:
        print(signature)

@exceptions_handler(Exception)
def print_rich_header(binary):
    print("== Rich Header ==")
    header = binary.rich_header
    print("Key: 0x{:08x}".format(header.key))

    for entry in header.entries:
        print("  - ID: {:04x} Build ID: {:04x} Count: {:d}".format(entry.id, entry.build_id, entry.count))
    print("")


@exceptions_handler(Exception)
def print_resources(binary):
    print("== Resources ==")
    manager = binary.resources_manager

    print(manager)

    print("")

@exceptions_handler(Exception)
def print_load_configuration(binary):
    format_str = "{:<45} {:<30}"
    format_hex = "{:<45} 0x{:<28x}"
    format_dec = "{:<45} {:<30d}"

    print("== Load Configuration ==")
    config = binary.load_configuration


    print(format_str.format("Version:",                          str(config.version).split(".")[-1]))
    print(format_dec.format("Characteristics:",                  config.characteristics))
    print(format_dec.format("Timedatestamp:",                    config.timedatestamp))
    print(format_dec.format("Major version:",                    config.major_version))
    print(format_dec.format("Minor version:",                    config.minor_version))
    print(format_hex.format("Global flags clear:",               config.global_flags_clear))
    print(format_hex.format("Global flags set:",                 config.global_flags_set))
    print(format_dec.format("Critical section default timeout:", config.critical_section_default_timeout))
    print(format_hex.format("Decommit free block threshold:",    config.decommit_free_block_threshold))
    print(format_hex.format("Decommit total free threshold:",    config.decommit_total_free_threshold))
    print(format_hex.format("Lock prefix table:",                config.lock_prefix_table))
    print(format_hex.format("Maximum allocation size:",          config.maximum_allocation_size))
    print(format_hex.format("Virtual memory threshold:",         config.virtual_memory_threshold))
    print(format_hex.format("Process affinity mask:",            config.process_affinity_mask))
    print(format_hex.format("Process heap flags:",               config.process_heap_flags))
    print(format_hex.format("CSD Version:",                      config.csd_version))
    print(format_hex.format("Reserved 1:",                       config.reserved1))
    print(format_hex.format("Edit list:",                        config.editlist))
    print(format_hex.format("Security cookie:",                  config.security_cookie))

    if isinstance(config, lief.PE.LoadConfigurationV0):
        print(format_hex.format("SE handler table:", config.se_handler_table))
        print(format_dec.format("SE handler count:", config.se_handler_count))

    if isinstance(config, lief.PE.LoadConfigurationV1):
        flags_str = " - ".join(map(lambda e : str(e).split(".")[-1], config.guard_cf_flags_list))
        print(format_hex.format("GCF check function pointer:",    config.guard_cf_check_function_pointer))
        print(format_hex.format("GCF dispatch function pointer:", config.guard_cf_dispatch_function_pointer))
        print(format_hex.format("GCF function table :",           config.guard_cf_function_table))
        print(format_dec.format("GCF Function count :",           config.guard_cf_function_count))
        print("{:<45} {} (0x{:x})".format("Guard flags:", flags_str, int(config.guard_flags)))

    if isinstance(config, lief.PE.LoadConfigurationV2):
        code_integrity = config.code_integrity
        print("Code Integrity:")
        print(format_dec.format(" " * 3 + "Flags:",          code_integrity.flags))
        print(format_dec.format(" " * 3 + "Catalog:",        code_integrity.catalog))
        print(format_hex.format(" " * 3 + "Catalog offset:", code_integrity.catalog_offset))
        print(format_dec.format(" " * 3 + "Reserved:",       code_integrity.reserved))

    if isinstance(config, lief.PE.LoadConfigurationV3):
        print(format_hex.format("Guard address taken iat entry table:", config.guard_address_taken_iat_entry_table))
        print(format_hex.format("Guard address taken iat entry count:", config.guard_address_taken_iat_entry_count))
        print(format_hex.format("Guard long jump target table:",        config.guard_long_jump_target_table))
        print(format_hex.format("Guard long jump target count:",        config.guard_long_jump_target_count))


    if isinstance(config, lief.PE.LoadConfigurationV4):
        print(format_hex.format("Dynamic value relocation table:", config.dynamic_value_reloc_table))
        print(format_hex.format("Hybrid metadata pointer:",        config.hybrid_metadata_pointer))


    if isinstance(config, lief.PE.LoadConfigurationV5):
        print(format_hex.format("GRF failure routine:",                  config.guard_rf_failure_routine))
        print(format_hex.format("GRF failure routine function pointer:", config.guard_rf_failure_routine_function_pointer))
        print(format_hex.format("Dynamic value reloctable offset:",      config.dynamic_value_reloctable_offset))
        print(format_hex.format("Dynamic value reloctable section:",     config.dynamic_value_reloctable_section))


    if isinstance(config, lief.PE.LoadConfigurationV6):
        print(format_hex.format("GRF verify stackpointer function pointer:", config.guard_rf_verify_stackpointer_function_pointer))
        print(format_hex.format("Hotpatch table offset:",                    config.hotpatch_table_offset))


    if isinstance(config, lief.PE.LoadConfigurationV7):
        print(format_hex.format("Reserved 3:", config.reserved3))

    print("")


@exceptions_handler(Exception)
def print_ctor(binary):
    print("== Constructors ==\n")

    print("Functions: ({:d})".format(len(binary.ctor_functions)))
    for idx, f in enumerate(binary.ctor_functions):
        print("    [{:d}] {}: 0x{:x}".format(idx, f.name, f.address))


@exceptions_handler(Exception)
def print_exception_functions(binary):
    print("== Exception functions ==\n")

    print("Functions: ({:d})".format(len(binary.exception_functions)))
    for idx, f in enumerate(binary.exception_functions):
        print("    [{:d}] {}: 0x{:x}".format(idx, f.name, f.address))


@exceptions_handler(Exception)
def print_functions(binary):
    print("== Functions ==\n")

    print("Functions: ({:d})".format(len(binary.functions)))
    for idx, f in enumerate(binary.functions):
        print("    [{:d}] {}: 0x{:x} ({:d} bytes)".format(idx, f.name, f.address, f.size))


@exceptions_handler(Exception)
def print_delay_imports(binary):
    delay_imports = binary.delay_imports
    if len(delay_imports) == 0:
        return
    print("== Delay Imports ==\n")
    for imp in delay_imports:
        print(imp.name)
        print("  Attribute:   {}".format(imp.attribute))
        print("  Handle:      0x{:x}".format(imp.handle))
        print("  IAT:         0x{:x}".format(imp.iat))
        print("  Names Table: 0x{:x}".format(imp.names_table))
        print("  Bound IAT:   0x{:x}".format(imp.biat))
        print("  Unload IAT:  0x{:x}".format(imp.uiat))
        print("  Timestamp:   0x{:x}".format(imp.timestamp))
        for entry in imp.entries:
            print("    {:<25} 0x{:08x}: 0x{:010x} - 0x{:x}".format(entry.name, entry.value, entry.iat_value, entry.hint))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pe_file")

    parser.add_argument('-a', '--all',
            action='store_true', dest='show_all',
            help='Show all informations')

    parser.add_argument('-d', '--data-directories',
            action='store_true', dest='show_data_directories',
            help='Display data directories')

    parser.add_argument('--dbg',
            action='store_true', dest='show_debug',
            help='Display debug directory')

    parser.add_argument('-g', '--signature',
            action='store_true', dest='show_signature',
            help="Display the binary's signature if any")

    parser.add_argument('-H', '--header',
            action='store_true', dest='show_headers',
            help='Display headers')

    parser.add_argument('-i', '--import',
            action='store_true', dest='show_imports',
            help='Display imported functions and libraries')

    parser.add_argument('--resolve-ordinals',
            action='store_true', dest='resolve_ordinals',
            help="When used with --import, it attempts to resolve names of ordinal imports")

    parser.add_argument('-r', '--relocs',
            action='store_true', dest='show_relocs',
            help='Display the relocations (if present)')

    parser.add_argument('-R', '--rich-header',
            action='store_true', dest='show_richheader',
            help='Display the Rich Header')

    parser.add_argument('--resources', '--rsrc',
            action='store_true', dest='show_resources',
            help='Display the resources (if present)')

    parser.add_argument('-S', '--section-headers', '--sections',
            action='store_true', dest='show_section_header',
            help="Display the sections' headers")

    parser.add_argument('-s', '--symbols', '--syms',
            action='store_true', dest='show_symbols',
            help='Display symbols')

    parser.add_argument('-t', '--tls',
            action='store_true', dest='show_tls',
            help='Display TLS informations')

    parser.add_argument('-x', '--export',
            action='store_true', dest='show_export',
            help='Display exported functions/libraries')

    parser.add_argument('--load-config',
            action='store_true', dest='show_loadconfig',
            help='Display load configuration')

    parser.add_argument('--ctor',
            action='store_true', dest='show_ctor',
            help='Constructor functions')

    parser.add_argument('-f', '--functions',
            action='store_true', dest='show_functions',
            help='Display all functions found in the binary')

    parser.add_argument('--exception-functions',
            action='store_true', dest='show_pfunctions',
            help='Display functions found in the exception directory')

    parser.add_argument('--delay-imports',
                        action='store_true', dest='show_delay_imports',
                        help='Display delay imports')

    # Logging setup
    logger_group = parser.add_argument_group('Logger')
    verbosity = logger_group.add_mutually_exclusive_group()

    verbosity.add_argument('--debug',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LEVEL.DEBUG)

    verbosity.add_argument('--trace',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LEVEL.TRACE)

    verbosity.add_argument('--info',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LEVEL.INFO)

    verbosity.add_argument('--warn',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LEVEL.WARN)

    verbosity.add_argument('--err',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LEVEL.ERROR)

    verbosity.add_argument('--critical',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LEVEL.CRITICAL)

    parser.set_defaults(main_verbosity=lief.logging.LEVEL.WARN)

    args = parser.parse_args()
    lief.logging.set_level(args.main_verbosity)

    binary = PE.parse(args.pe_file)

    if binary is None:
        sys.exit(1)

    print_information(binary)

    if args.show_data_directories or args.show_all:
        print_data_directories(binary)

    if args.show_headers or args.show_all:
        print_header(binary)

    if (args.show_imports or args.show_all) and binary.has_imports:
        print_imports(binary, resolve=args.resolve_ordinals)

    if (args.show_relocs or args.show_all) and binary.has_relocations:
        print_relocations(binary)

    if args.show_section_header or args.show_all:
        print_sections(binary)

    if args.show_symbols or args.show_all:
        print_symbols(binary)

    if (args.show_tls or args.show_all) and binary.has_tls:
        print_tls(binary)

    if (args.show_export or args.show_all) and binary.has_exports:
        print_export(binary)

    if (args.show_debug or args.show_all) and binary.has_debug:
        print_debug(binary)

    if (args.show_signature or args.show_all) and binary.has_signatures:
        print_signature(binary)

    if (args.show_richheader or args.show_all) and binary.has_rich_header:
        print_rich_header(binary)

    if (args.show_resources or args.show_all) and binary.has_resources:
        print_resources(binary)

    if (args.show_loadconfig or args.show_all) and binary.has_configuration:
        print_load_configuration(binary)

    if args.show_ctor or args.show_all:
        print_ctor(binary)

    if args.show_functions or args.show_all:
        print_functions(binary)

    if args.show_pfunctions or args.show_all:
        print_exception_functions(binary)

    if args.show_delay_imports or args.show_all:
        print_delay_imports(binary)

if __name__ == "__main__":
    main()
