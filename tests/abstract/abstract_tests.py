#!/usr/bin/env python
import unittest
import lief
import tempfile
import sys
import subprocess
import stat
import os
import logging
import random

from subprocess import Popen

from unittest import TestCase
from utils import get_sample

class TestAbstract(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def get_abstract_binary(binary):
        return binary.abstract

    @staticmethod
    def get_raw(path):
        raw = None
        with open(path, "rb") as f:
            raw = f.read()
        return list(raw)

    def test_endianness(self):
        binary = TestAbstract.get_abstract_binary(lief.parse(get_sample('ELF/ELF32_x86_binary_ls.bin')))
        header = binary.header

        self.assertEqual(header.endianness, lief.ENDIANNESS.LITTLE)


        binary = TestAbstract.get_abstract_binary(lief.parse(get_sample('MachO/MachO64_x86-64_binary_id.bin')))
        header = binary.header

        self.assertEqual(header.endianness, lief.ENDIANNESS.LITTLE)


        binary = TestAbstract.get_abstract_binary(lief.parse(get_sample('PE/PE64_x86-64_binary_ConsoleApplication1.exe')))
        header = binary.header

        self.assertEqual(header.endianness, lief.ENDIANNESS.LITTLE)


    def test_format(self):
        binary = TestAbstract.get_abstract_binary(lief.parse(get_sample('ELF/ELF32_x86_binary_ls.bin')))
        self.assertEqual(binary.format, lief.EXE_FORMATS.ELF)


        binary = TestAbstract.get_abstract_binary(lief.parse(get_sample('MachO/MachO64_x86-64_binary_id.bin')))
        self.assertEqual(binary.format, lief.EXE_FORMATS.MACHO)


        binary = TestAbstract.get_abstract_binary(lief.parse(get_sample('PE/PE64_x86-64_binary_ConsoleApplication1.exe')))
        self.assertEqual(binary.format, lief.EXE_FORMATS.PE)

    def test_pie(self):
        binary = TestAbstract.get_abstract_binary(lief.parse(get_sample('ELF/ELF32_ARM_binary-pie_ls.bin')))
        self.assertEqual(binary.is_pie, True)

        binary = TestAbstract.get_abstract_binary(lief.parse(get_sample('MachO/MachO64_x86-64_binary_nm.bin')))
        self.assertEqual(binary.is_pie, True)

        binary = TestAbstract.get_abstract_binary(lief.parse(get_sample('PE/PE32_x86_binary_cmd.exe')))
        self.assertEqual(binary.is_pie, True)

        binary = TestAbstract.get_abstract_binary(lief.parse(get_sample('ELF/ELF64_x86-64_binary_ls.bin')))
        self.assertEqual(binary.is_pie, False)


    def test_ctor(self):
        binary = TestAbstract.get_abstract_binary(lief.parse(get_sample('PE/PE32_x86_binary_winhello-mingw.exe')))
        self.assertEqual([f.address for f in binary.ctor_functions], [0x4018e0, 0x401890])
        self.assertEqual(binary.imagebase, 0x400000)

        binary = TestAbstract.get_abstract_binary(lief.parse(get_sample('MachO/MachO64_x86-64_binary_all.bin')))
        self.assertEqual([f.address for f in binary.ctor_functions], [0x100000dd0])
        self.assertEqual(binary.imagebase, 0x100000000)

        binary = TestAbstract.get_abstract_binary(lief.parse(get_sample('ELF/ELF64_x86-64_binary_gcc.bin')))
        self.assertEqual([f.address for f in binary.ctor_functions], [4206768, 4206416, 4203936])
        self.assertEqual(binary.imagebase, 0x400000)
        self.assertEqual(binary.offset_to_virtual_address(0xd4f38), 0x6d4f38)

        binary = TestAbstract.get_abstract_binary(lief.parse(get_sample('MachO/MachO64_x86-64_binary_sshd.bin')))
        self.assertEqual(binary.offset_to_virtual_address(0x18f001), 0x10019a001)

        #binary = TestAbstract.get_abstract_binary(lief.parse(get_sample('ELF/ELF64_AArch64_piebinary_ndkr16.bin')))
        #self.assertEqual(binary.ctor_functions, [0x4030b0, 0x402f50])


    #def test_parser(self):
    #    binary = lief.parse(TestAbstract.get_raw(get_sample('ELF/ELF32_x86_binary_ls.bin')))
    #    self.assertTrue(isinstance(binary, lief.ELF.Binary))


    #    binary = lief.parse(TestAbstract.get_raw(get_sample('MachO/MachO64_x86-64_binary_id.bin')))
    #    self.assertTrue(isinstance(binary, lief.MachO.Binary))

    #    binary = lief.parse(TestAbstract.get_raw(get_sample('MachO/FAT_MachO_x86_x86-64_library_libc.dylib')))
    #    self.assertTrue(isinstance(binary, lief.MachO.Binary))


    #    binary = lief.parse(TestAbstract.get_raw(get_sample('PE/PE64_x86-64_binary_ConsoleApplication1.exe')))
    #    self.assertTrue(isinstance(binary, lief.PE.Binary))


if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)

