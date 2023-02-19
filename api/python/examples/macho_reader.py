#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Description
# -----------
# Print information about a Mach-O binary

import sys
import os
import argparse
import traceback
import lief
from lief import MachO

terminal_rows, terminal_columns = 100, 100
try:
    terminal_rows, terminal_columns = os.popen('stty size', 'r').read().split()
except ValueError:
    pass

terminal_columns = int(terminal_columns)
terminal_rows    = int(terminal_rows)
EXIT_STATUS = 0

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
            global EXIT_STATUS
            print("{} raised: {}".format(self.func.__name__, e))
            EXIT_STATUS = 1
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
    print("== Information ==")
    format_str = "{:<30} {:<30}"
    format_hex = "{:<30} 0x{:<28x}"
    format_dec = "{:<30} {:<30d}"
    header: lief.MachO.Header = binary.header
    cpu = str(header.cpu_type).split('.')[-1]


    print(format_str.format("Name:",         binary.name))
    print(format_hex.format("Address base:", binary.imagebase))
    print(format_str.format("PIE:",          str(binary.is_pie)))
    print(format_str.format("NX:",           str(binary.has_nx)))
    print(format_str.format("Arch:",         cpu))
    print("")

@exceptions_handler(Exception)
def print_header(binary):
    format_str = "{:<33} {:<30}"
    format_hex = "{:<33} 0x{:<28x}"
    format_dec = "{:<33} {:<30d}"

    print("== Header ==")
    header = binary.header
    flags_str =  " - ".join([str(s).split(".")[-1] for s in header.flags_list])

    print(format_str.format("Magic:",              str(header.magic).split(".")[-1]))
    print(format_str.format("CPU Type:",           str(header.cpu_type).split(".")[-1]))
    print(format_hex.format("CPU sub-type:",       header.cpu_subtype))
    print(format_str.format("File Type:",          str(header.file_type).split(".")[-1]))
    print(format_str.format("Flags:",              flags_str))
    print(format_dec.format("Number of commands:", header.nb_cmds))
    print(format_hex.format("Size of commands:",   header.sizeof_cmds))
    print(format_hex.format("Reserved:",           header.reserved))

@exceptions_handler(Exception)
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

@exceptions_handler(Exception)
def print_libraries(binary):

    f_title = "|{:<30}|{:<10}|{:<16}|{:<22}|"
    f_value = "|{:<30}|{:<10d}|{:<16}|{:<22}|"
    print("== Libraries ==")
    print(f_title.format("Name", "Timestamp", "Current Version", "Compatibility Version"))
    for library in binary.libraries:
        current_version_str = "{:d}.{:d}.{:d}".format(*library.current_version)
        compatibility_version_str = "{:d}.{:d}.{:d}".format(*library.compatibility_version)
        print(f_value.format(
            library.name,
            library.timestamp,
            current_version_str,
            compatibility_version_str))
    print("")

@exceptions_handler(Exception)
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
            segment.file_offset,
            segment.file_size,
            segment.max_protection,
            segment.init_protection,
            sections))

    print("")

@exceptions_handler(Exception)
def print_sections(binary):

    f_title = "|{:<20}|{:<16}|{:<16}|{:<16}|{:16}|{:22}|{:19}|{:25}|{:25}|"
    f_value = "|{:<20}|0x{:<13x} |0x{:<13x} |0x{:<13x} |0x{:<13x} |0x{:<19x} |0x{:<16x} |{:<25}|{:<25}"

    print("== Sections ==")

    print(f_title.format(
        "Name", "Virtual Address", "Offset", "Size",
        "Alignement", "Number of Relocations", "Relocation offset",
        "Type", "Flags"))




    for section in binary.sections:
        flags_str =  " - ".join([str(s).split(".")[-1] for s in section.flags_list])
        print(f_value.format(
            section.name,
            section.virtual_address,
            section.offset,
            section.size,
            section.alignment,
            section.numberof_relocations,
            section.relocation_offset,
            str(section.type).split(".")[-1],
            flags_str))
        if len(section.relocations) > 0:
            for idx, reloc in enumerate(section.relocations):
                name = reloc.symbol.name if reloc.has_symbol else ""
                secname = " - " + reloc.section.name if reloc.has_section else ""
                type = str(reloc.type)
                if reloc.architecture == MachO.CPU_TYPES.x86:
                    type = str(MachO.X86_RELOCATION(reloc.type))

                if reloc.architecture == MachO.CPU_TYPES.x86_64:
                    type = str(MachO.X86_64_RELOCATION(reloc.type))

                if reloc.architecture == MachO.CPU_TYPES.ARM:
                    type = str(MachO.ARM_RELOCATION(reloc.type))

                if reloc.architecture == MachO.CPU_TYPES.ARM64:
                    type = str(MachO.ARM64_RELOCATION(reloc.type))

                if reloc.architecture == MachO.CPU_TYPES.POWERPC:
                    type = str(MachO.PPC_RELOCATION(reloc.type))


                print("    [Reloc #{:d} {section}] {name:<10} 0x{address:<6x} {type:<20} {size:d} {pcrel} {scat}".format(
                    idx,
                    section=secname,
                    name=name,
                    address=reloc.address,
                    type=type.split(".")[-1],
                    size=reloc.size,
                    pcrel=str(reloc.pc_relative),
                    scat=str(reloc.is_scattered)))
            print("")


    print("")

@exceptions_handler(Exception)
def print_symbols(binary):
    symbols = binary.symbols
    if len(symbols) == 0:
        return
    try:
        maxsize = max([len(symbol.demangled_name) for symbol in symbols])
    except:
        maxsize = max([len(symbol.name) for symbol in symbols])
    maxsize = min(maxsize, terminal_columns - 90) if terminal_columns > 90 else terminal_columns

    f_title = "|{:<" + str(maxsize) + "} |{:<6}|{:<19}|{:<16}|{:16}| {:s}"
    f_value = "|{:<" + str(maxsize) + "} |0x{:<3x} |0x{:<16x} |0x{:<13x} |0x{:<13x} | {:s}"
    print("== Symbols ==")
    print(f_title.format(
        "Name", "Type", "Number of Sections", "Description", "Value", "Library"))
    for symbol in binary.symbols:
        libname = ""
        if symbol.has_binding_info and symbol.binding_info.has_library:
            libname = symbol.binding_info.library.name


        symbol_value = 0
        if symbol.has_export_info:
            symbol_value = symbol.export_info.address
        elif symbol.has_binding_info:
            symbol_value = symbol.binding_info.address
        else:
            symbol_value = symbol.value

        try:
            symbol_name = symbol.demangled_name
        except:
            symbol_name = symbol.name
        print(f_value.format(
            symbol_name,
            symbol.type,
            symbol.numberof_sections,
            symbol.description,
            symbol_value,
            libname))
    print("")

@exceptions_handler(Exception)
def print_symbol_command(binary):
    print("== Symbol Command ==")

    scmd = binary.symbol_command

    format_str = "{:<17} {:<30}"
    format_hex = "{:<17} 0x{:<28x}"
    format_dec = "{:<17} {:<30d}"

    print(format_hex.format("Symbol offset", scmd.symbol_offset))
    print(format_dec.format("Number of symbols", scmd.numberof_symbols))

    print(format_hex.format("String offset", scmd.strings_offset))
    print(format_hex.format("String size", scmd.strings_size))

    print("")

@exceptions_handler(Exception)
def print_dynamic_symbol_command(binary):
    print("== Dynamic Symbol Command ==")

    dyscmd = binary.dynamic_symbol_command

    format_str = "{:<36} {:<30}"
    format_hex = "{:<36} 0x{:<28x}"
    format_dec = "{:<36} {:<30d}"

    print(format_dec.format("First local symbol index", dyscmd.idx_local_symbol))
    print(format_dec.format("Number of local symbols", dyscmd.nb_local_symbols))

    print(format_dec.format("External symbol index", dyscmd.idx_external_define_symbol))
    print(format_dec.format("Number of external symbols", dyscmd.nb_external_define_symbols))

    print(format_dec.format("Undefined symbol index", dyscmd.idx_undefined_symbol))
    print(format_dec.format("Number of undefined symbols", dyscmd.nb_undefined_symbols))

    print(format_dec.format("Table of content offset", dyscmd.toc_offset))
    print(format_dec.format("Number of entries in TOC", dyscmd.nb_toc))

    print(format_hex.format("Module table offset", dyscmd.module_table_offset))
    print(format_dec.format("Number of entries in module table", dyscmd.nb_module_table))

    print(format_hex.format("External reference table offset", dyscmd.external_reference_symbol_offset))
    print(format_dec.format("Number of external reference", dyscmd.nb_external_reference_symbols))

    print(format_hex.format("Indirect symbols offset", dyscmd.indirect_symbol_offset))
    print(format_dec.format("Number of indirect symbols", dyscmd.nb_indirect_symbols))

    print(format_hex.format("External relocation offset", dyscmd.external_relocation_offset))
    print(format_dec.format("Number of external relocations", dyscmd.nb_external_relocations))

    print(format_hex.format("Local relocation offset", dyscmd.local_relocation_offset))
    print(format_dec.format("Number of local relocations", dyscmd.nb_local_relocations))

    print("")


@exceptions_handler(Exception)
def print_uuid(binary):
    print("== UUID ==")
    cmd = binary.uuid
    uuid_str = " ".join(map(lambda e : "{:02x}".format(e), cmd.uuid))
    print("UUID: {}".format(uuid_str))

    print("")


@exceptions_handler(Exception)
def print_main_command(binary):

    format_str = "{:<13} {:<30}"
    format_hex = "{:<13} 0x{:<28x}"
    format_dec = "{:<13} {:<30d}"

    print("== Main Command ==")
    cmd = binary.main_command

    print(format_hex.format("Entry point:", cmd.entrypoint))
    print(format_hex.format("Stack size:", cmd.stack_size))

    print("")


@exceptions_handler(Exception)
def print_thread_command(binary):

    format_str = "{:<13} {:<30}"
    format_hex = "{:<13} 0x{:<28x}"
    format_dec = "{:<13} {:<30d}"

    print("== Thread Command ==")
    cmd = binary.thread_command

    print(format_hex.format("Flavor:", cmd.flavor))
    print(format_hex.format("Count:",  cmd.count))
    print(format_hex.format("PC:",     cmd.pc))

    print("")

@exceptions_handler(Exception)
def print_rpath_command(binary):

    format_str = "{:<13} {:<30}"
    format_hex = "{:<13} 0x{:<28x}"
    format_dec = "{:<13} {:<30d}"

    print("== Rpath Command ==")
    cmd = binary.rpath
    print("Path: {}".format(cmd.path))


    print("")



@exceptions_handler(Exception)
def print_dylinker(binary):
    print("== Dylinker ==")
    print("Path: {}".format(binary.dylinker.name))

    print("")

@exceptions_handler(Exception)
def print_function_starts(binary):
    format_str = "{:<13} {:<30}"
    format_hex = "{:<13} 0x{:<28x}"
    format_dec = "{:<13} {:<30d}"

    print("== Function Starts ==")

    fstarts = binary.function_starts

    print(format_hex.format("Offset:", fstarts.data_offset))
    print(format_hex.format("Size:",   fstarts.data_size))
    print("Functions: ({:d})".format(len(fstarts.functions)))
    for idx, address in enumerate(fstarts.functions):
        print("    [{:d}] __TEXT + 0x{:x}".format(idx, address))

    print("")

@exceptions_handler(Exception)
def print_data_in_code(binary):
    format_str = "{:<13} {:<30}"
    format_hex = "{:<13} 0x{:<28x}"
    format_dec = "{:<13} {:<30d}"

    print("== Data In Code ==")

    datacode = binary.data_in_code

    print(format_hex.format("Offset:", datacode.data_offset))
    print(format_hex.format("Size:",   datacode.data_size))
    print("")
    for entry in datacode.entries:
        type_str = str(entry.type).split(".")[-1]
        print("- {:<14}: 0x{:x} ({:d} bytes)".format(type_str, entry.offset, entry.length))
    print("")


@exceptions_handler(Exception)
def print_segment_split_info(binary):
    format_str = "{:<13} {:<30}"
    format_hex = "{:<13} 0x{:<28x}"
    format_dec = "{:<13} {:<30d}"

    print("== Segment Split Info ==")

    sinfo = binary.segment_split_info

    print(format_hex.format("Offset:", sinfo.data_offset))
    print(format_hex.format("Size:",   sinfo.data_size))

    print("")


@exceptions_handler(Exception)
def print_sub_framework(binary):
    format_str = "{:<13} {:<30}"
    format_hex = "{:<13} 0x{:<28x}"
    format_dec = "{:<13} {:<30d}"

    print("== Sub Framework ==")

    sinfo = binary.sub_framework
    print(format_str.format("Umbrella:", sinfo.umbrella))

    print("")

@exceptions_handler(Exception)
def print_dyld_environment(binary):
    format_str = "{:<13} {:<30}"
    format_hex = "{:<13} 0x{:<28x}"
    format_dec = "{:<13} {:<30d}"

    print("== Dyld Environment ==")

    env = binary.dyld_environment
    print(format_str.format("Value:", env.value))

    print("")


@exceptions_handler(Exception)
def print_dyld_info(binary):
    print("== Dyld Info ==")
    f_title = "|{:<12}|{:<11}|{:<11}|"
    f_value = "|{:<12}|0x{:<8x} |0x{:<8x} |"

    dyld_info = binary.dyld_info

    print(f_title.format("Type", "Offset", "Size"))
    print(f_value.format("Rebase",    dyld_info.rebase[0],      dyld_info.rebase[1]))
    print(f_value.format("Bind",      dyld_info.bind[0],        dyld_info.bind[1]))
    print(f_value.format("Weak Bind", dyld_info.weak_bind[0],   dyld_info.weak_bind[1]))
    print(f_value.format("Lazy Bind", dyld_info.lazy_bind[0],   dyld_info.lazy_bind[1]))
    print(f_value.format("Export",    dyld_info.export_info[0], dyld_info.export_info[1]))

    print("")

    print("Bindings")
    print("--------")
    for idx, binfo in enumerate(dyld_info.bindings):
        print("{:10}: {}".format("Class", str(binfo.binding_class).split(".")[-1]))
        print("{:10}: {}".format("Type", str(binfo.binding_type).split(".")[-1]))
        print("{:10}: {:x}".format("Address", binfo.address))

        if binfo.has_symbol:
            print("{:10}: {}".format("Symbol", binfo.symbol.name))

        if binfo.has_segment:
            print("{:10}: {}".format("Segment", binfo.segment.name))

        if binfo.has_library:
            print("{:10}: {}".format("Library", binfo.library.name))

        if binfo.binding_class == lief.MachO.BINDING_CLASS.LAZY:
            print("{:10}: {}".format("Offset", binfo.original_offset))

        print("")

    print("")

    print("Exports")
    print("-------")
    for idx, einfo in enumerate(dyld_info.exports):
        output = "0x{:08x} - {}".format(einfo.address, einfo.symbol.name)
        if einfo.alias:
            output += " - {}".format(einfo.alias.name)
            if einfo.alias_library:
                output += " from {}".format(einfo.alias_library.name)
        print(output)

        #print("{:10}: {:<10x}".format("Address", einfo.address))
        #print("{:10}: {:<10x}".format("Flags", einfo.flags))

        #if binfo.has_symbol:
        #    print("{:10}: {}".format("Symbol", einfo.symbol.name))

        print("")



    print("")


@exceptions_handler(Exception)
def print_rebase_opcodes(binary):
    print("== Rebase opcodes ==")

    print(binary.dyld_info.show_rebases_opcodes)

    print("")

@exceptions_handler(Exception)
def print_bind_opcodes(binary):
    print("== Bind opcodes ==")

    print(binary.dyld_info.show_bind_opcodes)

    print("")

@exceptions_handler(Exception)
def print_weak_bind_opcodes(binary):
    print("== Weak bind opcodes ==")

    print(binary.dyld_info.show_weak_bind_opcodes)

    print("")

@exceptions_handler(Exception)
def print_lazy_bind_opcodes(binary):
    print("== Lazy bind opcodes ==")

    print(binary.dyld_info.show_lazy_bind_opcodes)

    print("")

@exceptions_handler(Exception)
def print_export_trie(binary):
    print("== Export trie ==")
    if binary.has_dyld_info:
        print(binary.dyld_info.show_export_trie)
    if binary.has_dyld_exports_trie:
        trie: lief.MachO.DyldExportsTrie = binary.dyld_exports_trie
        print("Linkedit position: 0x{} (0x{:x} bytes)".format(trie.data_offset, trie.data_size))
        print(trie.show_export_trie())

    print("")

@exceptions_handler(Exception)
def print_source_version(binary):
    print("== Source Version ==")

    version = binary.source_version.version

    print("Version: {:d}.{:d}.{:d}.{:d}.{:d}".format(*version))

    print("")


@exceptions_handler(Exception)
def print_version_min(binary):
    print("== Version Min ==")

    version = binary.version_min.version
    sdk     = binary.version_min.sdk

    print("Version: {:d}.{:d}.{:d}".format(*version))
    print("SDK: {:d}.{:d}.{:d}".format(*sdk))

    print("")


@exceptions_handler(Exception)
def print_relocations(binary):
    print("== Relocations ==")

    f_value = "|0x{address:<10x} | {size:<4d} | {type:<15} | {pcrel:<11} | {secseg:<23} | {symbol}"
    f_title = "|{address:<12} | {size:<4} | {type:<15} | {pcrel:<11} | {secseg:<23} | {symbol}"

    print(f_title.format(
        address="Address",
        size="Size",
        type="Type",
        pcrel="PC Relative",
        secseg="Section/Section",
        symbol="Symbol"))


    for reloc in binary.relocations:
        type_str = ""
        if reloc.origin == lief.MachO.RELOCATION_ORIGINS.DYLDINFO:
            type_str = str(lief.MachO.REBASE_TYPES(reloc.type)).split(".")[-1]

        if reloc.origin == lief.MachO.RELOCATION_ORIGINS.RELOC_TABLE:
            if reloc.architecture == MachO.CPU_TYPES.x86:
                type_str = str(MachO.X86_RELOCATION(reloc.type))

            if reloc.architecture == MachO.CPU_TYPES.x86_64:
                type_str = str(MachO.X86_64_RELOCATION(reloc.type))

            if reloc.architecture == MachO.CPU_TYPES.ARM:
                type_str = str(MachO.ARM_RELOCATION(reloc.type))

            if reloc.architecture == MachO.CPU_TYPES.ARM64:
                type_str = str(MachO.ARM64_RELOCATION(reloc.type))

            if reloc.architecture == MachO.CPU_TYPES.POWERPC:
                type_str = str(MachO.PPC_RELOCATION(reloc.type))

            type_str = type_str.split(".")[-1]

        symbol_name = ""
        if reloc.has_symbol:
            symbol_name = reloc.symbol.name

        secseg_name = ""
        if reloc.has_segment and reloc.has_section:
            secseg_name = "{}.{}".format(reloc.segment.name, reloc.section.name)
        else:
            if reloc.has_segment:
                secseg_name = reloc.segment.name

            if reloc.has_section:
                secseg_name = reloc.section.name

        print(f_value.format(
            address=reloc.address,
            size=reloc.size,
            type=type_str,
            pcrel=str(reloc.pc_relative),
            secseg=secseg_name,
            symbol=symbol_name))


    print("")

@exceptions_handler(Exception)
def print_encryption_info(binary):

    format_str = "{:<13} {:<30}"
    format_hex = "{:<13} 0x{:<28x}"
    format_dec = "{:<13} {:<30d}"

    print("== Encryption Info ==")
    cmd = binary.encryption_info

    print(format_hex.format("Offset:", cmd.crypt_offset))
    print(format_hex.format("Size:",   cmd.crypt_size))
    print(format_dec.format("ID:",     cmd.crypt_id))

    print("")


@exceptions_handler(Exception)
def print_ctor(binary):
    print("== Constructors ==\n")

    print("Functions: ({:d})".format(len(binary.ctor_functions)))
    for idx, f in enumerate(binary.ctor_functions):
        print("    [{:d}] {}: 0x{:x}".format(idx, f.name, f.address))


@exceptions_handler(Exception)
def print_unwind_functions(binary):
    print("== Unwind functions ==\n")

    print("Functions: ({:d})".format(len(binary.unwind_functions)))
    for idx, f in enumerate(binary.unwind_functions):
        print("    [{:d}] {}: 0x{:x}".format(idx, f.name, f.address))

@exceptions_handler(Exception)
def print_functions(binary):
    print("== Functions ==\n")

    print("Functions: ({:d})".format(len(binary.functions)))
    for idx, f in enumerate(binary.functions):
        print("    [{:d}] {}: 0x{:x}".format(idx, f.name, f.address))

@exceptions_handler(Exception)
def print_build_version(binary):
    print("== Build Version ==\n")

    build_version = binary.build_version

    print("Platform: {}".format(str(build_version.platform).split(".")[-1]))
    print("Min OS: {:d}.{:d}.{:d}".format(*build_version.minos))
    print("SDK: {:d}.{:d}.{:d}".format(*build_version.sdk))

    tools = build_version.tools
    if len(tools) > 0:
        print("~~ Tools ({}) ~~".format(len(tools)))
        for tool in tools:
            tool_str = str(tool.tool).split(".")[-1]
            print("    {} - {}.{}.{}".format(tool_str, *tool.version))

def print_chained_fixups(binary: lief.MachO.Binary):
    if not binary.has_dyld_chained_fixups:
        return
    print("== Dyld Chained Fixups ==")
    fixups: lief.MachO.DyldChainedFixups = binary.dyld_chained_fixups
    print(fixups)


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

    parser.add_argument('-r', '--relocations',
            action='store_true', dest='show_relocs',
            help='Display the relocations (if present)')

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

    parser.add_argument('--dyldinfo',
            action='store_true', dest='show_dyldinfo',
            help='Display the DyldInfo command')

    parser.add_argument('--function-starts',
            action='store_true', dest='show_function_starts',
            help='Display the FunctionStarts command')

    parser.add_argument('--rebase-opcodes',
            action='store_true', dest='show_rebase_opcodes',
            help='Display the "Rebase" opcodes')

    parser.add_argument('--source-version',
            action='store_true', dest='show_source_version',
            help="Display the 'Source Version' command")

    parser.add_argument('--version-min',
            action='store_true', dest='show_version_min',
            help="Display the 'Version Min' command")

    parser.add_argument('--thread-command',
            action='store_true', dest='show_thread_command',
            help="Display the 'Thread Command' command")

    parser.add_argument('--rpath-command',
            action='store_true', dest='show_rpath_command',
            help="Display the 'Rpath Command' command")

    parser.add_argument('--symbol-command',
            action='store_true', dest='show_symbol_command',
            help="Display the 'Symbol Command' command")

    parser.add_argument('--dynamic-symbol-command',
            action='store_true', dest='show_dynamic_symbol_command',
            help="Display the 'Symbol Command' command")

    parser.add_argument('--data-in-code',
            action='store_true', dest='show_data_in_code',
            help="Display the 'Data In Code' command")

    parser.add_argument('--segment-split-info',
            action='store_true', dest='show_segment_split_info',
            help="Display the 'Segment Split Info' command")

    parser.add_argument('--sub-framework',
            action='store_true', dest='show_sub_framework',
            help="Display the 'Sub Framework' command")

    parser.add_argument('--dyld-environment',
            action='store_true', dest='show_dyld_env',
            help="Display the 'Dyld Environment' command")

    parser.add_argument('--encryption-info',
            action='store_true', dest='show_encrypt_info',
            help="Display the 'Encryption Info' command")

    parser.add_argument('--bind-opcodes',
            action='store_true', dest='show_bind_opcodes',
            help='Display the "Bind" opcodes')

    parser.add_argument('--weak-bind-opcodes',
            action='store_true', dest='show_weak_bind_opcodes',
            help='Display the "Weak Bind" opcodes')

    parser.add_argument('--lazy-bind-opcodes',
            action='store_true', dest='show_lazy_bind_opcodes',
            help='Display the "Lazy Bind" opcodes')

    parser.add_argument('--export-trie',
            action='store_true', dest='show_export_trie',
            help='Display the export trie')

    parser.add_argument('--opcodes',
            action='store_true', dest='show_opcodes',
            help='Display the bind and rebase opcodes')

    parser.add_argument('--ctor',
            action='store_true', dest='show_ctor',
            help='Constructor functions')

    parser.add_argument('--unwind-functions',
            action='store_true', dest='show_ufunctions',
            help='Functions from unwind info')

    parser.add_argument('--functions',
            action='store_true', dest='show_functions',
            help='All functions found in the binary')

    parser.add_argument('--build-version',
            action='store_true', dest='show_build_version',
            help='Show build version')

    parser.add_argument('--chained-fixups',
            action='store_true', dest='show_chained_fixups',
            help='Show Dyld Chained Fixups')

    parser.add_argument('--check-layout',
            action='store_true', dest='check_layout',
            help='Check the layout of the binary')

    parser.add_argument("binary",
            metavar="<macho-file>",
            help='Target Mach-O File')

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

    binaries = MachO.parse(args.binary)
    if binaries is None:
        print("Can't parse {}".format(args.binary))
        sys.exit(1)

    if len(binaries) > 1:
        print("Fat Mach-O: {:d} binaries".format(len(binaries)))

    if args.check_layout:
        isok, err = MachO.check_layout(binaries)
        if not isok:
            print(err)

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

        if (args.show_dyldinfo or args.show_all) and binary.has_dyld_info:
            print_dyld_info(binary)

        if (args.show_function_starts or args.show_all) and binary.has_function_starts:
            print_function_starts(binary)

        if (args.show_source_version or args.show_all) and binary.has_source_version:
            print_source_version(binary)

        if (args.show_version_min or args.show_all) and binary.has_version_min:
            print_version_min(binary)

        if (args.show_relocs or args.show_all) and len(binary.relocations) > 0:
            print_relocations(binary)

        if (args.show_thread_command or args.show_all) and binary.has_thread_command:
            print_thread_command(binary)

        if (args.show_rpath_command or args.show_all) and binary.has_rpath:
            print_rpath_command(binary)

        if (args.show_symbol_command or args.show_all) and binary.has_symbol_command:
            print_symbol_command(binary)

        if (args.show_dynamic_symbol_command or args.show_all) and binary.has_dynamic_symbol_command:
            print_dynamic_symbol_command(binary)

        if (args.show_data_in_code or args.show_all) and binary.has_data_in_code:
            print_data_in_code(binary)

        if (args.show_segment_split_info or args.show_all) and binary.has_segment_split_info:
            print_segment_split_info(binary)

        if (args.show_sub_framework or args.show_all) and binary.has_sub_framework:
            print_sub_framework(binary)

        if (args.show_dyld_env or args.show_all) and binary.has_dyld_environment:
            print_dyld_environment(binary)

        if (args.show_encrypt_info or args.show_all) and binary.has_encryption_info:
            print_encryption_info(binary)

        if (args.show_rpath_command or args.show_all) and binary.has_rpath:
            print_rpath_command(binary)

        if (args.show_rebase_opcodes or args.show_opcodes) and binary.has_dyld_info:
            print_rebase_opcodes(binary)

        if (args.show_bind_opcodes  or args.show_opcodes) and binary.has_dyld_info:
            print_bind_opcodes(binary)

        if (args.show_weak_bind_opcodes or args.show_opcodes) and binary.has_dyld_info:
            print_weak_bind_opcodes(binary)

        if (args.show_lazy_bind_opcodes or args.show_opcodes) and binary.has_dyld_info:
            print_lazy_bind_opcodes(binary)

        if (args.show_export_trie or args.show_opcodes):
            print_export_trie(binary)

        if args.show_ctor or args.show_all:
            print_ctor(binary)

        if args.show_ufunctions or args.show_all:
            print_unwind_functions(binary)

        if args.show_functions or args.show_all:
            print_functions(binary)

        if (args.show_build_version or args.show_all) and binary.has_build_version:
            print_build_version(binary)

        if args.show_chained_fixups or args.show_all:
            print_chained_fixups(binary)


    sys.exit(EXIT_STATUS)


if __name__ == "__main__":
    main()
