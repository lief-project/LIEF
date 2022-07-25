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

lief.logging.set_level(lief.logging.LOGGING_LEVEL.INFO)

class TestSimple(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

        self.binall = lief.parse(get_sample('ELF/ELF32_x86_binary_all.bin'))

    def test_header(self):
        self.assertEqual(self.binall.interpreter, "/lib/ld-linux.so.2")
        self.assertEqual(self.binall.entrypoint, 0x774)

    def test_sections(self):
        self.assertEqual(len(self.binall.sections), 32)

        self.assertTrue(self.binall.has_section(".tdata"))

        text_section = self.binall.get_section(".text")

        self.assertEqual(text_section.type, lief.ELF.SECTION_TYPES.PROGBITS)
        self.assertEqual(text_section.offset, 0x6D0)
        self.assertEqual(text_section.virtual_address, 0x6D0)
        self.assertEqual(text_section.size, 0x271)
        self.assertEqual(text_section.alignment, 16)
        self.assertIn(lief.ELF.SECTION_FLAGS.ALLOC, text_section)
        self.assertIn(lief.ELF.SECTION_FLAGS.EXECINSTR, text_section)


    def test_segments(self):
        segments = self.binall.segments
        self.assertEqual(len(segments), 10)

        LOAD_0 = segments[2]
        LOAD_1 = segments[3]

        self.assertEqual(LOAD_0.type, lief.ELF.SEGMENT_TYPES.LOAD)
        self.assertEqual(LOAD_0.file_offset, 0)
        self.assertEqual(LOAD_0.virtual_address, 0)
        self.assertEqual(LOAD_0.physical_size, 0x00b34)
        self.assertEqual(LOAD_0.virtual_size, 0x00b34)
        self.assertEqual(int(LOAD_0.flags), lief.ELF.SEGMENT_FLAGS.R | lief.ELF.SEGMENT_FLAGS.X)

        self.assertEqual(LOAD_1.type, lief.ELF.SEGMENT_TYPES.LOAD)
        self.assertEqual(LOAD_1.file_offset, 0x000ed8)
        self.assertEqual(LOAD_1.virtual_address, 0x00001ed8)
        self.assertEqual(LOAD_1.physical_address, 0x00001ed8)
        self.assertEqual(LOAD_1.physical_size, 0x00148)
        self.assertEqual(LOAD_1.virtual_size, 0x0014c)
        self.assertEqual(int(LOAD_1.flags), lief.ELF.SEGMENT_FLAGS.R | lief.ELF.SEGMENT_FLAGS.W)


    def test_dynamic(self):
        entries = self.binall.dynamic_entries
        self.assertEqual(len(entries), 28)
        self.assertEqual(entries[0].name, "libc.so.6")
        self.assertEqual(entries[3].array, [2208, 1782])
        self.assertEqual(self.binall[lief.ELF.DYNAMIC_TAGS.FLAGS_1].value, 0x8000000)

    def test_relocations(self):
        dynamic_relocations = self.binall.dynamic_relocations
        pltgot_relocations = self.binall.pltgot_relocations

        self.assertEqual(len(dynamic_relocations), 10)
        self.assertEqual(len(pltgot_relocations), 3)

        self.assertEqual(dynamic_relocations[0].address, 0x00001edc)
        self.assertEqual(dynamic_relocations[8].symbol.name, "__gmon_start__")
        self.assertEqual(dynamic_relocations[9].address, 0x00001ffc)

        self.assertEqual(pltgot_relocations[1].address, 0x00002010)
        self.assertEqual(pltgot_relocations[1].symbol.name, "puts")
        self.assertEqual(pltgot_relocations[1].info, 4)

    def test_symbols(self):
        dynamic_symbols = self.binall.dynamic_symbols
        static_symbols  = self.binall.static_symbols

        self.assertEqual(len(dynamic_symbols), 27)
        self.assertEqual(len(static_symbols), 78)

        first = self.binall.get_dynamic_symbol("first")
        self.assertEqual(first.value, 0x000008a9)
        self.assertEqual(first.symbol_version.value, 0x8002)
        self.assertEqual(first.symbol_version.symbol_version_auxiliary.name, "LIBSIMPLE_1.0")

        dtor = self.binall.get_static_symbol("__cxa_finalize@@GLIBC_2.1.3")
        self.assertEqual(dtor.value, 00000000)

        symbol_version_definition   = self.binall.symbols_version_definition
        symbols_version_requirement = self.binall.symbols_version_requirement
        symbols_version             = self.binall.symbols_version

        self.assertEqual(len(symbol_version_definition), 2)
        self.assertEqual(len(symbols_version_requirement), 1)
        self.assertEqual(len(symbols_version), 27)

        self.assertEqual(symbol_version_definition[0].hash, 0x63ca0e)
        self.assertEqual(symbol_version_definition[0].version, 1)
        self.assertEqual(symbol_version_definition[0].flags, 1)
        self.assertEqual(symbol_version_definition[0].auxiliary_symbols[0].name, "all-32.bin")

        self.assertEqual(symbol_version_definition[1].auxiliary_symbols[0].name, "LIBSIMPLE_1.0")

        self.assertEqual(symbols_version_requirement[0].name, "libc.so.6")
        self.assertEqual(symbols_version_requirement[0].version, 1)

        self.assertEqual(symbols_version[0].value, 0)

    def test_notes(self):
        notes = self.binall.notes
        self.assertEqual(len(notes), 2)

        self.assertEqual(notes[0].details.abi, lief.ELF.NOTE_ABIS.LINUX)
        self.assertEqual(notes[0].description, [0, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0])
        self.assertEqual(notes[0].name, "GNU")
        self.assertEqual(notes[0].type, lief.ELF.NOTE_TYPES.ABI_TAG)
        self.assertEqual(notes[0].details.version, [3, 2, 0])


class TestSectionless(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

        self.sectionless = lief.ELF.parse(get_sample('ELF/ELF64_x86-64_binary_rvs.bin'), lief.ELF.DYNSYM_COUNT_METHODS.HASH)

    def test_symbols(self):
        symbols = self.sectionless.dynamic_symbols
        self.assertEqual(len(symbols), 10)

        self.assertEqual(symbols[2].name, "_IO_putc")

    def test_relocations(self):
        relocations = self.sectionless.relocations
        self.assertEqual(len(relocations), 10)

        self.assertEqual(relocations[0].symbol.name, "__gmon_start__")

class TestObject(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

        self.obj = lief.parse(get_sample('ELF/ELF64_x86-64_object_builder.o'))

    def test_relocations(self):
        pass


class TestCorrupted(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

        self.corrupted = lief.parse(get_sample('ELF/ELF32_x86_library_libshellx.so'))

    def test_symbols(self):
        symbols = [sym for idx, sym in enumerate(self.corrupted.dynamic_symbols) if idx == 0 or len(sym.name) > 0]
        self.assertEqual(len(symbols), 48)

        self.assertEqual(symbols[2].name, "__cxa_atexit")

    def test_relocations(self):
        relocations = self.corrupted.relocations
        self.assertEqual(len(relocations), 47)

        self.assertEqual(relocations[10].symbol.name, "strlen")


class TestGcc(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)


    def test_symbol_count(self):

        gcc1 = lief.ELF.parse(get_sample('ELF/ELF32_x86_binary_gcc.bin'), lief.ELF.DYNSYM_COUNT_METHODS.HASH)
        gcc2 = lief.ELF.parse(get_sample('ELF/ELF32_x86_binary_gcc.bin'), lief.ELF.DYNSYM_COUNT_METHODS.SECTION)
        gcc3 = lief.ELF.parse(get_sample('ELF/ELF32_x86_binary_gcc.bin'), lief.ELF.DYNSYM_COUNT_METHODS.RELOCATIONS)

        self.assertEqual(len(gcc1.symbols), 158)
        self.assertEqual(len(gcc2.symbols), 158)
        self.assertEqual(len(gcc3.symbols), 158)


class TestTiny(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

        self.tiny01 = lief.parse(get_sample('ELF/ELF32_x86_binary_tiny01.bin'))

    def test_segment(self):
        self.assertEqual(len(self.tiny01.segments), 1)
        segment = self.tiny01.segments[0]

        self.assertEqual(segment.type, lief.ELF.SEGMENT_TYPES.LOAD)
        self.assertEqual(segment.file_offset, 0)
        self.assertEqual(segment.virtual_address, 0x8048000)
        self.assertEqual(segment.physical_size, 0x5a)
        self.assertEqual(segment.virtual_size, 0x5a)
        self.assertEqual(int(segment.flags), lief.ELF.SEGMENT_FLAGS.R | lief.ELF.SEGMENT_FLAGS.X)

class TestAllRelocs(TestCase):
    """
    Test binary generated with all relocation sections.
    """

    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.bin_with_relocs = lief.parse(get_sample('ELF/ELF64_x86-64_hello-with-relocs.bin'))

    def test_relocations(self):
        relocations = self.bin_with_relocs.relocations
        self.assertEqual(len(relocations), 37)
        # check relocation from .rela.text
        self.assertEqual(relocations[12].symbol.name,"main")
        self.assertEqual(relocations[12].address,0x1064)
        # check relocation from .rela.eh_frame
        self.assertTrue(relocations[30].has_section)
        self.assertEqual(relocations[30].address,0x2068)


class TestTinyAArch64(TestCase):
    """
    Test that the parser can process ELF files
    with corruped EI_CLASS
    cf. https://tmpout.sh/2/14.html
    """

    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.target = lief.parse(get_sample('ELF/tiny_aarch64.elf'))

    def test_tiny(self):
        self.assertEqual(len(self.target.segments), 1)
        self.assertEqual(self.target.segments[0].virtual_address, 0x100000000)
        self.assertEqual(self.target.segments[0].file_offset, 0)
        self.assertEqual(self.target.segments[0].physical_size, 0x17fffff2)
        self.assertEqual(len(self.target.segments[0].content), 84)
        if is_64bits_platform():
            self.assertEqual(lief.hash(self.target.segments[0].content), 2547808573126369212)


class TestCorruptedIdentity(TestCase):
    """
    Test that we do not (only) rely on EI_DATA / EI_CLASS
    to determine the ELFCLASS and the endianness
    cf. https://tmpout.sh/2/3.html
    """
    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.target = lief.parse(get_sample('ELF/hello_ei_data.elf'))

    def test_parser(self):
        self.assertEqual(len(self.target.segments), 10)


class TestArchitectures(TestCase):
    """
    Test we support uncommon architectures
    """
    def test_s390(self):
        s390 = lief.parse(get_sample("ELF/elf_reader.s390.elf"))
        self.assertEqual(len(s390.segments), 10)
        self.assertEqual(len(s390.sections), 32)
        self.assertEqual(len(s390.dynamic_symbols), 278)
        self.assertEqual(len(s390.dynamic_entries), 27)

    def test_xtensa(self):
       xtensa = lief.parse(get_sample("ELF/elf_reader.xtensa.elf"))
       self.assertEqual(len(xtensa.segments), 10)
       self.assertEqual(len(xtensa.sections), 30)
       self.assertEqual(len(xtensa.dynamic_symbols), 247)
       self.assertEqual(len(xtensa.dynamic_entries), 25)

    def test_mips(self):
       mips = lief.parse(get_sample("ELF/elf_reader.mips.elf"))
       self.assertEqual(len(mips.segments), 12)
       self.assertEqual(len(mips.sections), 39)
       self.assertEqual(len(mips.dynamic_symbols), 450)
       self.assertEqual(len(mips.dynamic_entries), 36)

    def test_riscv64(self):
       riscv64 = lief.parse(get_sample("ELF/elf_reader.riscv64.elf"))
       self.assertEqual(len(riscv64.segments), 10)
       self.assertEqual(len(riscv64.sections), 30)
       self.assertEqual(len(riscv64.dynamic_symbols), 439)
       self.assertEqual(len(riscv64.dynamic_entries), 29)

    def test_riscv32(self):
       riscv32 = lief.parse(get_sample("ELF/elf_reader.riscv32.elf"))
       self.assertEqual(len(riscv32.segments), 10)
       self.assertEqual(len(riscv32.sections), 30)
       self.assertEqual(len(riscv32.dynamic_symbols), 445)
       self.assertEqual(len(riscv32.dynamic_entries), 29)

    def test_ppc64le(self):
       ppc64le = lief.parse(get_sample("ELF/elf_reader.ppc64le.elf"))
       self.assertEqual(len(ppc64le.segments), 10)
       self.assertEqual(len(ppc64le.sections), 32)
       self.assertEqual(len(ppc64le.dynamic_symbols), 246)
       self.assertEqual(len(ppc64le.dynamic_entries), 29)

    def test_hexagon(self):
       hexagon = lief.parse(get_sample("ELF/modem.hexagon.elf"))
       self.assertEqual(len(hexagon.segments), 7)


if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)
