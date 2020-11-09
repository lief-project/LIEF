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
from utils import get_sample

lief.logging.set_level(lief.logging.LOGGING_LEVEL.WARNING)

class TestSimple(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

        self.winhello64 = lief.parse(get_sample('PE/PE64_x86-64_binary_winhello64-mingw.exe'))
        self.atapi = lief.parse(get_sample('PE/PE64_x86-64_atapi.sys'))

    def test_dos_header(self):
        pass
        #self.assertEqual(self.binall.interpreter, "/lib/ld-linux.so.2")
        #self.assertEqual(self.binall.entrypoint, 0x774)

    def test_header(self):
        pass

    def test_optional_header(self):
        pass

    def test_data_directories(self):
        pass

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


    def test_rich_header(self):
        rheader = self.atapi.rich_header
        self.assertEqual(rheader.key, 0xa476a6e3)

        entries = rheader.entries

        self.assertEqual(len(entries), 8)
        entry_4 = entries[4]

        self.assertEqual(entry_4.id, 0x95)
        self.assertEqual(entry_4.build_id, 0x7809)
        self.assertEqual(entry_4.count, 1)

    def test_resources(self):
        pass

    def test_relocations(self):
        pass

    def test_symbols(self):

        symbols = self.winhello64.symbols
        self.assertEqual(len(symbols), 1097)

        symbol = symbols[1]
        self.assertEqual(symbol.name, "__mingw_invalidParameterHandler")
        self.assertEqual(symbol.value, 0)
        self.assertEqual(symbol.section_number, 1)
        self.assertEqual(symbol.type, 32)

    def test_exports(self):
        pass


class TestPacker(TestCase):

    def test_upx(self):
        pass


class TestCorrupted(TestCase):
    def test_weird(self):
        pass


if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)
