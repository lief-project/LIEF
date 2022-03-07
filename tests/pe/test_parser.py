#!/usr/bin/env python
import itertools
import logging
import os
import random
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import TestCase

import lief
from utils import get_sample, is_64bits_platform

lief.logging.set_level(lief.logging.LOGGING_LEVEL.ERROR)

class TestSimple(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

        self.winhello64 = lief.parse(get_sample('PE/PE64_x86-64_binary_winhello64-mingw.exe'))
        self.atapi = lief.parse(get_sample('PE/PE64_x86-64_atapi.sys'))

    def test_dos_header(self):
        dos_header: lief.PE.DosHeader = self.atapi.dos_header

        self.assertEqual(dos_header.addressof_new_exeheader, 0xd8)
        self.assertEqual(dos_header.addressof_relocation_table, 0x40)
        self.assertEqual(dos_header.checksum, 0x0)
        self.assertEqual(dos_header.file_size_in_pages, 0x3)
        self.assertEqual(dos_header.header_size_in_paragraphs, 0x4)
        self.assertEqual(dos_header.initial_ip, 0x0)
        self.assertEqual(dos_header.initial_relative_cs, 0x0)
        self.assertEqual(dos_header.initial_relative_ss, 0x0)
        self.assertEqual(dos_header.initial_sp, 0xb8)
        self.assertEqual(dos_header.magic, 0x5a4d)
        self.assertEqual(dos_header.maximum_extra_paragraphs, 0xffff)
        self.assertEqual(dos_header.minimum_extra_paragraphs, 0x0)
        self.assertEqual(dos_header.numberof_relocation, 0x0)
        self.assertEqual(dos_header.oem_id, 0x0)
        self.assertEqual(dos_header.oem_info, 0x0)
        self.assertEqual(dos_header.overlay_number, 0x0)
        self.assertEqual(dos_header.used_bytes_in_the_last_page, 0x90)

    def test_header(self):
        header: lief.PE.Header = self.atapi.header

        self.assertEqual(header.numberof_sections, 0x6)
        self.assertEqual(header.numberof_symbols, 0x0)
        self.assertEqual(header.pointerto_symbol_table, 0x0)
        self.assertEqual(header.signature, [80, 69, 0, 0])
        self.assertEqual(header.sizeof_optional_header, 0xf0)
        self.assertEqual(header.time_date_stamps, 0x4a5bc113)
        self.assertEqual(header.machine, lief.PE.MACHINE_TYPES.AMD64)
        self.assertEqual(header.characteristics_list, {lief.PE.HEADER_CHARACTERISTICS.LARGE_ADDRESS_AWARE, lief.PE.HEADER_CHARACTERISTICS.EXECUTABLE_IMAGE})

    def test_optional_header(self):
        header: lief.PE.OptionalHeader = self.atapi.optional_header

        self.assertEqual(header.addressof_entrypoint, 0x7064)
        self.assertEqual(header.baseof_code, 0x1000)
        self.assertEqual(header.checksum, 0x65bb)
        self.assertEqual(header.dll_characteristics, 0x0)
        self.assertEqual(header.file_alignment, 0x200)
        self.assertEqual(header.imagebase, 0x10000)
        self.assertEqual(header.loader_flags, 0x0)
        self.assertEqual(header.magic, lief.PE.PE_TYPE.PE32_PLUS)
        self.assertEqual(header.major_image_version, 0x6)
        self.assertEqual(header.major_linker_version, 0x9)
        self.assertEqual(header.major_operating_system_version, 0x6)
        self.assertEqual(header.major_subsystem_version, 0x6)
        self.assertEqual(header.minor_image_version, 0x1)
        self.assertEqual(header.minor_linker_version, 0x0)
        self.assertEqual(header.minor_operating_system_version, 0x1)
        self.assertEqual(header.minor_subsystem_version, 0x1)
        self.assertEqual(header.numberof_rva_and_size, 0x10)
        self.assertEqual(header.section_alignment, 0x1000)
        self.assertEqual(header.sizeof_code, 0x3200)
        self.assertEqual(header.sizeof_headers, 0x400)
        self.assertEqual(header.sizeof_heap_commit, 0x1000)
        self.assertEqual(header.sizeof_heap_reserve, 0x100000)
        self.assertEqual(header.sizeof_image, 0x9000)
        self.assertEqual(header.sizeof_initialized_data, 0xc00)
        self.assertEqual(header.sizeof_stack_commit, 0x1000)
        self.assertEqual(header.sizeof_stack_reserve, 0x40000)
        self.assertEqual(header.sizeof_uninitialized_data, 0x0)
        self.assertEqual(header.subsystem, lief.PE.SUBSYSTEM.NATIVE)
        self.assertEqual(header.win32_version_value, 0x0)

    def test_data_directories(self):
        dirs = self.atapi.data_directories

        self.assertEqual(dirs[0].rva, 0x0)
        self.assertEqual(dirs[0].size, 0x0)
        self.assertEqual(dirs[0].has_section, False)

        self.assertEqual(dirs[1].rva, 0x7084)
        self.assertEqual(dirs[1].size, 0x3c)
        self.assertEqual(dirs[1].has_section, True)
        self.assertEqual(dirs[1].section.name, "INIT")

        self.assertEqual(dirs[2].rva, 0x8000)
        self.assertEqual(dirs[2].size, 0x3f0)
        self.assertEqual(dirs[2].has_section, True)
        self.assertEqual(dirs[2].section.name, ".rsrc")

        self.assertEqual(dirs[3].rva, 0x6000)
        self.assertEqual(dirs[3].size, 0x1e0)
        self.assertEqual(dirs[3].has_section, True)
        self.assertEqual(dirs[3].section.name, ".pdata")

        self.assertEqual(dirs[4].rva, 0x4200)
        self.assertEqual(dirs[4].size, 0x1c40)
        self.assertEqual(dirs[4].has_section, True)
        self.assertEqual(dirs[4].section.name, ".rdata")

        self.assertEqual(dirs[5].rva, 0x0)
        self.assertEqual(dirs[5].size, 0x0)
        self.assertEqual(dirs[5].has_section, False)

        self.assertEqual(dirs[6].rva, 0x40d0)
        self.assertEqual(dirs[6].size, 0x1c)
        self.assertEqual(dirs[6].has_section, True)
        self.assertEqual(dirs[6].section.name, ".rdata")

        self.assertEqual(dirs[7].rva, 0x0)
        self.assertEqual(dirs[7].size, 0x0)
        self.assertEqual(dirs[7].has_section, False)

        self.assertEqual(dirs[8].rva, 0x0)
        self.assertEqual(dirs[8].size, 0x0)
        self.assertEqual(dirs[8].has_section, False)

        self.assertEqual(dirs[9].rva, 0x0)
        self.assertEqual(dirs[9].size, 0x0)
        self.assertEqual(dirs[9].has_section, False)

        self.assertEqual(dirs[10].rva, 0x0)
        self.assertEqual(dirs[10].size, 0x0)
        self.assertEqual(dirs[10].has_section, False)

        self.assertEqual(dirs[11].rva, 0x0)
        self.assertEqual(dirs[11].size, 0x0)
        self.assertEqual(dirs[11].has_section, False)

        self.assertEqual(dirs[12].rva, 0x4000)
        self.assertEqual(dirs[12].size, 0xd0)
        self.assertEqual(dirs[12].has_section, True)
        self.assertEqual(dirs[12].section.name, ".rdata")

        self.assertEqual(dirs[13].rva, 0x0)
        self.assertEqual(dirs[13].size, 0x0)
        self.assertEqual(dirs[13].has_section, False)

        self.assertEqual(dirs[14].rva, 0x0)
        self.assertEqual(dirs[14].size, 0x0)
        self.assertEqual(dirs[14].has_section, False)

        self.assertEqual(dirs[15].rva, 0x0)
        self.assertEqual(dirs[15].size, 0x0)
        self.assertEqual(dirs[15].has_section, False)

    def test_sections(self):
        sections = self.winhello64.sections

        self.assertEqual(len(sections), 17)

        section = sections[4]

        self.assertEqual(section.name, ".xdata")
        self.assertEqual(section.offset, 0x3200)
        self.assertEqual(section.size, 0x400)
        self.assertEqual(section.virtual_address, 0x6000)
        self.assertEqual(section.virtual_size, 0x204)
        self.assertEqual(section.characteristics, 0x40300040)

        sections = self.atapi.sections
        self.assertEqual(sections[0].name, ".text")
        self.assertEqual(sections[0].virtual_size, 0x2be4)
        self.assertEqual(sections[0].virtual_address, 0x1000)
        self.assertEqual(sections[0].sizeof_raw_data, 0x2c00)
        self.assertEqual(sections[0].pointerto_raw_data, 0x400)
        self.assertEqual(sections[0].pointerto_relocation, 0x0)
        self.assertEqual(sections[0].pointerto_line_numbers, 0x0)
        self.assertEqual(sections[0].numberof_relocations, 0x0)
        self.assertEqual(sections[0].numberof_line_numbers, 0x0)
        self.assertEqual(int(sections[0].characteristics), 0x68000020)
        if is_64bits_platform():
            self.assertEqual(lief.hash(list(sections[0].padding)), 0xffffffffc691aee8)
            self.assertEqual(lief.hash(list(sections[0].content)), 0x2023e2e)

        self.assertEqual(sections[1].name, ".rdata")
        self.assertEqual(sections[1].virtual_size, 0x2b4)
        self.assertEqual(sections[1].virtual_address, 0x4000)
        self.assertEqual(sections[1].sizeof_raw_data, 0x400)
        self.assertEqual(sections[1].pointerto_raw_data, 0x3000)
        self.assertEqual(sections[1].pointerto_relocation, 0x0)
        self.assertEqual(sections[1].pointerto_line_numbers, 0x0)
        self.assertEqual(sections[1].numberof_relocations, 0x0)
        self.assertEqual(sections[1].numberof_line_numbers, 0x0)
        self.assertEqual(int(sections[1].characteristics), 0x48000040)

        if is_64bits_platform():
            self.assertEqual(lief.hash(list(sections[1].padding)), 0xffffffffdc061565)
            self.assertEqual(lief.hash(list(sections[1].content)), 0x7f4ae4d9)

        self.assertEqual(sections[2].name, ".data")
        self.assertEqual(sections[2].virtual_size, 0x114)
        self.assertEqual(sections[2].virtual_address, 0x5000)
        self.assertEqual(sections[2].sizeof_raw_data, 0x200)
        self.assertEqual(sections[2].pointerto_raw_data, 0x3400)
        self.assertEqual(sections[2].pointerto_relocation, 0x0)
        self.assertEqual(sections[2].pointerto_line_numbers, 0x0)
        self.assertEqual(sections[2].numberof_relocations, 0x0)
        self.assertEqual(sections[2].numberof_line_numbers, 0x0)
        self.assertEqual(int(sections[2].characteristics), 0xc8000040)

        if is_64bits_platform():
            self.assertEqual(lief.hash(list(sections[2].padding)), 0x391e5290)
            self.assertEqual(lief.hash(list(sections[2].content)), 0x2109ac81)

        self.assertEqual(sections[3].name, ".pdata")
        self.assertEqual(sections[3].virtual_size, 0x1e0)
        self.assertEqual(sections[3].virtual_address, 0x6000)
        self.assertEqual(sections[3].sizeof_raw_data, 0x200)
        self.assertEqual(sections[3].pointerto_raw_data, 0x3600)
        self.assertEqual(sections[3].pointerto_relocation, 0x0)
        self.assertEqual(sections[3].pointerto_line_numbers, 0x0)
        self.assertEqual(sections[3].numberof_relocations, 0x0)
        self.assertEqual(sections[3].numberof_line_numbers, 0x0)
        self.assertEqual(int(sections[3].characteristics), 0x48000040)

        if is_64bits_platform():
            self.assertEqual(lief.hash(list(sections[3].padding)), 0xd5f2925)
            self.assertEqual(lief.hash(list(sections[3].content)), 0x13f38a3e)

        self.assertEqual(sections[4].name, "INIT")
        self.assertEqual(sections[4].virtual_size, 0x42a)
        self.assertEqual(sections[4].virtual_address, 0x7000)
        self.assertEqual(sections[4].sizeof_raw_data, 0x600)
        self.assertEqual(sections[4].pointerto_raw_data, 0x3800)
        self.assertEqual(sections[4].pointerto_relocation, 0x0)
        self.assertEqual(sections[4].pointerto_line_numbers, 0x0)
        self.assertEqual(sections[4].numberof_relocations, 0x0)
        self.assertEqual(sections[4].numberof_line_numbers, 0x0)
        self.assertEqual(int(sections[4].characteristics), 0xe2000020)

        if is_64bits_platform():
            self.assertEqual(lief.hash(list(sections[4].padding)), 0xffffffff93471cc1)
            self.assertEqual(lief.hash(list(sections[4].content)), 0xffffffffb3ea2b8b)

        self.assertEqual(sections[5].name, ".rsrc")
        self.assertEqual(sections[5].virtual_size, 0x3f0)
        self.assertEqual(sections[5].virtual_address, 0x8000)
        self.assertEqual(sections[5].sizeof_raw_data, 0x400)
        self.assertEqual(sections[5].pointerto_raw_data, 0x3e00)
        self.assertEqual(sections[5].pointerto_relocation, 0x0)
        self.assertEqual(sections[5].pointerto_line_numbers, 0x0)
        self.assertEqual(sections[5].numberof_relocations, 0x0)
        self.assertEqual(sections[5].numberof_line_numbers, 0x0)
        self.assertEqual(int(sections[5].characteristics), 0x42000040)

        if is_64bits_platform():
            self.assertEqual(lief.hash(list(sections[5].padding)), 0x28ec37bb)
            self.assertEqual(lief.hash(list(sections[5].content)), 0x65f49890)

    def test_tls(self):
        self.assertTrue(self.winhello64.has_tls)

        tls = self.winhello64.tls

        self.assertEqual(tls.addressof_callbacks, 0x409040)
        self.assertEqual(tls.callbacks, [0x4019c0, 0x401990])
        self.assertEqual(tls.addressof_index, 0x4075fc)
        self.assertEqual(tls.sizeof_zero_fill, 0)
        self.assertEqual(tls.characteristics, 0)
        self.assertEqual(tls.addressof_raw_data, (0x40a000, 0x40a060))
        self.assertEqual(tls.section.name, ".tls")

    def test_imports(self):
        imports  = self.winhello64.imports

        self.assertEqual(len(imports), 2)

        kernel32 = imports[0]
        self.assertEqual(kernel32.name, "KERNEL32.dll")
        self.assertEqual(kernel32.import_address_table_rva, 0x81fc)
        self.assertEqual(kernel32.import_lookup_table_rva, 0x803C)
        self.assertEqual(len(kernel32.entries), 25)

        entry_12 = kernel32.entries[12]
        self.assertEqual(entry_12.name, "LeaveCriticalSection")
        self.assertEqual(entry_12.data, 0x84ba)
        self.assertEqual(entry_12.hint, 0x34b)
        self.assertEqual(entry_12.iat_value, 0x84ba)
        self.assertEqual(entry_12.iat_address, 0x825c)

        msvcrt = imports[1]
        self.assertEqual(msvcrt.name, "msvcrt.dll")
        self.assertEqual(msvcrt.import_address_table_rva, 0x82cc)
        self.assertEqual(msvcrt.import_lookup_table_rva, 0x810c)
        self.assertEqual(len(msvcrt.entries), 29)

        entry_0 = msvcrt.entries[0]
        self.assertEqual(entry_0.name, "__C_specific_handler")
        self.assertEqual(entry_0.data, 0x85ca )
        self.assertEqual(entry_0.hint, 55)
        self.assertEqual(entry_0.iat_value, 0x85ca )
        self.assertEqual(entry_0.iat_address, 0x82cc)

    def test_issue_imports(self):
        pe: lief.PE.Binary = lief.parse(get_sample("PE/abdce8577b46e4e23346f06ba8b9ab05cf47e92aec7e615c04436301355cd86d.pe"))
        imports = pe.imports

        self.assertEqual(len(imports), 9)
        entry_7 = imports[8]
        self.assertEqual(len(entry_7.entries), 6)
        self.assertEqual(entry_7.entries[0].name, "GetModuleHandleA")
        self.assertEqual(entry_7.entries[5].name, "ExitProcess")

    def test_issue_exports(self):
        pe: lief.PE.Binary = lief.parse(get_sample("PE/24e3ea78835748c9995e0d0c64f4f6bd3a0ca1b495b61a601703eb19b8c27f95.pe"))
        exports = pe.get_export()

        self.assertEqual(exports.name, "Uniscribe.dll")
        self.assertEqual(exports.export_flags, 0)
        self.assertEqual(exports.timestamp, 1446632214)
        self.assertEqual(exports.major_version, 0)
        self.assertEqual(exports.minor_version, 0)
        self.assertEqual(exports.ordinal_base, 1)
        self.assertEqual(len(exports.entries), 7)

        self.assertEqual(exports.entries[0].name, "GetModuleFileNameDll")
        self.assertEqual(exports.entries[0].ordinal, 1)
        self.assertEqual(exports.entries[0].address, 0x15bd0)
        self.assertEqual(exports.entries[0].is_extern, False)
        self.assertEqual(exports.entries[0].function_rva, 0x15bd0)

        self.assertEqual(exports.entries[6].name, "ncProxyXll")
        self.assertEqual(exports.entries[6].ordinal, 7)
        self.assertEqual(exports.entries[6].address, 0x203a0)
        self.assertEqual(exports.entries[6].is_extern, False)
        self.assertEqual(exports.entries[6].function_rva, 0x203a0)

    def test_rich_header(self):
        rheader = self.atapi.rich_header
        self.assertEqual(rheader.key, 0xa476a6e3)

        entries = rheader.entries

        self.assertEqual(len(entries), 7)
        entry_4 = entries[4]

        self.assertEqual(entry_4.id, 0x95)
        self.assertEqual(entry_4.build_id, 0x7809)
        self.assertEqual(entry_4.count, 1)
        hex_val = bytes(rheader.raw(rheader.key)).hex()
        self.assertEqual(hex_val,
                         "a7c718f7e3a676a4e3a676a4e3a676a4"
                         "eadee5a4e6a676a4e3a677a4fba676a4"
                         "eadee3a4e2a676a4eadef5a4e0a676a4"
                         "eadeffa4e1a676a4eadee2a4e2a676a4"
                         "eadee7a4e2a676a452696368e3a676a4")

        sha256 = bytes(rheader.hash(lief.PE.ALGORITHMS.SHA_256, rheader.key)).hex()
        self.assertEqual(sha256, "1bda7d55023ff27b0ea1c9f56d53ca77ca4264ac58fdee8daac58cdc060bf2da")



    def test_relocations(self):
        pe: lief.PE.Binary = lief.parse(get_sample("PE/PE64_x86-64_binary_mfc-application.exe"))
        relocations = pe.relocations
        self.assertEqual(relocations[0].virtual_address, 0xd000)
        self.assertEqual(relocations[0].block_size, 0xb8)
        self.assertEqual(len(relocations[0].entries), 88)
        relocation = relocations[0]

        self.assertEqual(relocation.entries[46].data, 0xaeb8)
        self.assertEqual(relocation.entries[46].position, 0xeb8)
        self.assertEqual(relocation.entries[46].type, lief.PE.RELOCATIONS_BASE_TYPES.DIR64)
        self.assertEqual(relocation.entries[25].data, 0xae10)
        self.assertEqual(relocation.entries[25].position, 0xe10)
        self.assertEqual(relocation.entries[25].type, lief.PE.RELOCATIONS_BASE_TYPES.DIR64)
        self.assertEqual(relocation.entries[56].data, 0xaf08)
        self.assertEqual(relocation.entries[56].position, 0xf08)
        self.assertEqual(relocation.entries[56].type, lief.PE.RELOCATIONS_BASE_TYPES.DIR64)
        self.assertEqual(relocation.entries[75].data, 0xafa0)
        self.assertEqual(relocation.entries[75].position, 0xfa0)
        self.assertEqual(relocation.entries[75].type, lief.PE.RELOCATIONS_BASE_TYPES.DIR64)

        self.assertEqual(relocations[8].virtual_address, 0x15000)
        self.assertEqual(relocations[8].block_size, 0xc0)
        self.assertEqual(len(relocations[8].entries), 92)
        relocation = relocations[8]
        self.assertEqual(relocation.entries[87].data, 0xa9f8)
        self.assertEqual(relocation.entries[87].position, 0x9f8)
        self.assertEqual(relocation.entries[87].type, lief.PE.RELOCATIONS_BASE_TYPES.DIR64)
        self.assertEqual(relocation.entries[24].data, 0xa0c0)
        self.assertEqual(relocation.entries[24].position, 0xc0)
        self.assertEqual(relocation.entries[24].type, lief.PE.RELOCATIONS_BASE_TYPES.DIR64)
        self.assertEqual(relocation.entries[67].data, 0xa218)
        self.assertEqual(relocation.entries[67].position, 0x218)
        self.assertEqual(relocation.entries[67].type, lief.PE.RELOCATIONS_BASE_TYPES.DIR64)
        self.assertEqual(relocation.entries[54].data, 0xa1b0)
        self.assertEqual(relocation.entries[54].position, 0x1b0)
        self.assertEqual(relocation.entries[54].type, lief.PE.RELOCATIONS_BASE_TYPES.DIR64)

        self.assertEqual(relocations[9].virtual_address, 0x1c000)
        self.assertEqual(relocations[9].block_size, 0x80)
        self.assertEqual(len(relocations[9].entries), 60)
        relocation = relocations[9]
        self.assertEqual(relocation.entries[40].data, 0xa628)
        self.assertEqual(relocation.entries[40].position, 0x628)
        self.assertEqual(relocation.entries[40].type, lief.PE.RELOCATIONS_BASE_TYPES.DIR64)
        self.assertEqual(relocation.entries[17].data, 0xa2d8)
        self.assertEqual(relocation.entries[17].position, 0x2d8)
        self.assertEqual(relocation.entries[17].type, lief.PE.RELOCATIONS_BASE_TYPES.DIR64)
        self.assertEqual(relocation.entries[36].data, 0xa5a0)
        self.assertEqual(relocation.entries[36].position, 0x5a0)
        self.assertEqual(relocation.entries[36].type, lief.PE.RELOCATIONS_BASE_TYPES.DIR64)
        self.assertEqual(relocation.entries[52].data, 0xa7f8)
        self.assertEqual(relocation.entries[52].position, 0x7f8)
        self.assertEqual(relocation.entries[52].type, lief.PE.RELOCATIONS_BASE_TYPES.DIR64)


    def test_symbols(self):

        symbols = self.winhello64.symbols
        self.assertEqual(len(symbols), 1097)

        symbol = symbols[1]
        self.assertEqual(symbol.name, "__mingw_invalidParameterHandler")
        self.assertEqual(symbol.value, 0)
        self.assertEqual(symbol.section_number, 1)
        self.assertEqual(symbol.type, 32)


    def test_checksum(self):
        self.assertEqual(self.atapi.optional_header.computed_checksum,
                         self.atapi.optional_header.checksum)
        self.assertEqual(self.winhello64.optional_header.computed_checksum,
                         self.winhello64.optional_header.checksum)

if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)
