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
import itertools

from subprocess import Popen

from unittest import TestCase
from utils import get_sample

class TestMachODyld(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_exports_trie(self):
        target = lief.parse(get_sample('MachO/MachO64_x86-64_binary_exports-trie-LLVM.bin'))
        self.assertTrue(target.has_dyld_info)
        exports = target.dyld_info.exports

        self.assertEqual(len(exports), 6)

        self.assertEqual(exports[0].address, 1)
        self.assertEqual(exports[0].symbol.name, "_malloc")

        self.assertEqual(exports[1].address, 1)
        self.assertEqual(exports[1].symbol.name, "_myfree")

        self.assertEqual(exports[2].address, 0xf70)
        self.assertEqual(exports[2].symbol.name, "_myWeak")

        self.assertEqual(exports[3].address, 0x1018)
        self.assertEqual(exports[3].symbol.name, "_myTLV")

        self.assertEqual(exports[4].address, 0x12345678)
        self.assertEqual(exports[4].symbol.name, "_myAbs")

        self.assertEqual(exports[5].address, 0xf60)
        self.assertEqual(exports[5].symbol.name, "_foo")


    def test_bind(self):
        target = lief.parse(get_sample('MachO/MachO64_x86-64_binary_bind-LLVM.bin'))
        self.assertTrue(target.has_dyld_info)
        bindings = target.dyld_info.bindings

        self.assertEqual(len(bindings), 7)

        self.assertEqual(bindings[0].binding_class, lief.MachO.BINDING_CLASS.STANDARD)
        self.assertEqual(bindings[0].binding_type, lief.MachO.BIND_TYPES.POINTER)
        self.assertEqual(bindings[0].address, 0x1028)
        self.assertEqual(bindings[0].symbol.name, "_any")
        self.assertEqual(bindings[0].segment.name, "__DATA")
        self.assertEqual(bindings[0].library_ordinal, -2)

        self.assertEqual(bindings[1].binding_class, lief.MachO.BINDING_CLASS.STANDARD)
        self.assertEqual(bindings[1].binding_type, lief.MachO.BIND_TYPES.POINTER)
        self.assertEqual(bindings[1].address, 0x1020)
        self.assertEqual(bindings[1].symbol.name, "_fromApp")
        self.assertEqual(bindings[1].segment.name, "__DATA")
        self.assertEqual(bindings[1].library_ordinal, -1)

        self.assertEqual(bindings[2].binding_class, lief.MachO.BINDING_CLASS.STANDARD)
        self.assertEqual(bindings[2].binding_type, lief.MachO.BIND_TYPES.POINTER)
        self.assertEqual(bindings[2].address, 0x1018)
        self.assertEqual(bindings[2].symbol.name, "_myfunc")
        self.assertEqual(bindings[2].segment.name, "__DATA")
        self.assertEqual(bindings[2].library_ordinal, 0)

        self.assertEqual(bindings[3].binding_class, lief.MachO.BINDING_CLASS.STANDARD)
        self.assertEqual(bindings[3].binding_type, lief.MachO.BIND_TYPES.POINTER)
        self.assertEqual(bindings[3].address, 0x1000)
        self.assertEqual(bindings[3].symbol.name, "_foo")
        self.assertEqual(bindings[3].segment.name, "__DATA")
        self.assertEqual(bindings[3].library.name, "libfoo.dylib")

        self.assertEqual(bindings[4].binding_class, lief.MachO.BINDING_CLASS.STANDARD)
        self.assertEqual(bindings[4].binding_type, lief.MachO.BIND_TYPES.POINTER)
        self.assertEqual(bindings[4].address, 0x1008)
        self.assertEqual(bindings[4].symbol.name, "_bar")
        self.assertEqual(bindings[4].segment.name, "__DATA")
        self.assertEqual(bindings[4].library.name, "libbar.dylib")

        self.assertEqual(bindings[5].binding_class, lief.MachO.BINDING_CLASS.STANDARD)
        self.assertEqual(bindings[5].binding_type, lief.MachO.BIND_TYPES.POINTER)
        self.assertEqual(bindings[5].address, 0x1010)
        self.assertEqual(bindings[5].symbol.name, "_malloc")
        self.assertEqual(bindings[5].segment.name, "__DATA")
        self.assertEqual(bindings[5].library.name, "/usr/lib/libSystem.B.dylib")


        # From Weak bind
        self.assertEqual(bindings[6].binding_class, lief.MachO.BINDING_CLASS.WEAK)
        self.assertEqual(bindings[6].binding_type, lief.MachO.BIND_TYPES.POINTER)
        self.assertEqual(bindings[6].address, 0x1000)
        self.assertEqual(bindings[6].symbol.name, "_foo")
        self.assertEqual(bindings[6].segment.name, "__DATA")


    def test_lazy_bind(self):
        target = lief.parse(get_sample('MachO/MachO64_x86-64_binary_lazy-bind-LLVM.bin'))
        self.assertTrue(target.has_dyld_info)
        bindings = list(target.dyld_info.bindings)[1:] # Skip the 1st one (Standard one)
        self.assertEqual(len(bindings), 3)

        self.assertEqual(bindings[0].binding_class, lief.MachO.BINDING_CLASS.LAZY)
        self.assertEqual(bindings[0].binding_type, lief.MachO.BIND_TYPES.POINTER)
        self.assertEqual(bindings[0].address, 0x100001010)
        self.assertEqual(bindings[0].symbol.name, "_foo")
        self.assertEqual(bindings[0].segment.name, "__DATA")
        self.assertEqual(bindings[0].library.name, "libfoo.dylib")

        self.assertEqual(bindings[1].binding_class, lief.MachO.BINDING_CLASS.LAZY)
        self.assertEqual(bindings[1].binding_type, lief.MachO.BIND_TYPES.POINTER)
        self.assertEqual(bindings[1].address, 0x100001018)
        self.assertEqual(bindings[1].symbol.name, "_bar")
        self.assertEqual(bindings[1].segment.name, "__DATA")
        self.assertEqual(bindings[1].library.name, "libbar.dylib")

        self.assertEqual(bindings[2].binding_class, lief.MachO.BINDING_CLASS.LAZY)
        self.assertEqual(bindings[2].binding_type, lief.MachO.BIND_TYPES.POINTER)
        self.assertEqual(bindings[2].address, 0x100001020)
        self.assertEqual(bindings[2].symbol.name, "_malloc")
        self.assertEqual(bindings[2].segment.name, "__DATA")
        self.assertEqual(bindings[2].library.name, "/usr/lib/libSystem.B.dylib")


    def test_rebases(self):
        target = lief.parse(get_sample('MachO/MachO64_x86-64_binary_rebase-LLVM.bin'))
        self.assertTrue(target.has_dyld_info)

        relocations = target.relocations

        self.assertEqual(len(relocations), 10)

        self.assertEqual(relocations[0].address, 0x00001010)
        self.assertEqual(relocations[0].pc_relative, False)
        self.assertEqual(relocations[0].type, lief.MachO.REBASE_TYPES.POINTER)
        self.assertEqual(relocations[0].section.name, "__data")
        self.assertEqual(relocations[0].segment.name, "__DATA")

        self.assertEqual(relocations[1].address, 0x00001028)
        self.assertEqual(relocations[1].pc_relative, False)
        self.assertEqual(relocations[1].type, lief.MachO.REBASE_TYPES.POINTER)
        self.assertEqual(relocations[1].section.name, "__data")
        self.assertEqual(relocations[1].segment.name, "__DATA")

        self.assertEqual(relocations[2].address, 0x00001030)
        self.assertEqual(relocations[2].pc_relative, False)
        self.assertEqual(relocations[2].type, lief.MachO.REBASE_TYPES.POINTER)
        self.assertEqual(relocations[2].section.name, "__data")
        self.assertEqual(relocations[2].segment.name, "__DATA")

        self.assertEqual(relocations[3].address, 0x00001038)
        self.assertEqual(relocations[3].pc_relative, False)
        self.assertEqual(relocations[3].type, lief.MachO.REBASE_TYPES.POINTER)
        self.assertEqual(relocations[3].section.name, "__data")
        self.assertEqual(relocations[3].segment.name, "__DATA")

        self.assertEqual(relocations[4].address, 0x00001040)
        self.assertEqual(relocations[4].pc_relative, False)
        self.assertEqual(relocations[4].type, lief.MachO.REBASE_TYPES.POINTER)
        self.assertEqual(relocations[4].section.name, "__data")
        self.assertEqual(relocations[4].segment.name, "__DATA")

        self.assertEqual(relocations[5].address, 0x00001258)
        self.assertEqual(relocations[5].pc_relative, False)
        self.assertEqual(relocations[5].type, lief.MachO.REBASE_TYPES.POINTER)
        self.assertEqual(relocations[5].section.name, "__data")
        self.assertEqual(relocations[5].segment.name, "__DATA")


        self.assertEqual(relocations[6].address, 0x00001278)
        self.assertEqual(relocations[6].pc_relative, False)
        self.assertEqual(relocations[6].type, lief.MachO.REBASE_TYPES.POINTER)
        self.assertEqual(relocations[6].section.name, "__mystuff")
        self.assertEqual(relocations[6].segment.name, "__DATA")

        self.assertEqual(relocations[7].address, 0x00001288)
        self.assertEqual(relocations[7].pc_relative, False)
        self.assertEqual(relocations[7].type, lief.MachO.REBASE_TYPES.POINTER)
        self.assertEqual(relocations[7].section.name, "__mystuff")
        self.assertEqual(relocations[7].segment.name, "__DATA")

        self.assertEqual(relocations[8].address, 0x00001298)
        self.assertEqual(relocations[8].pc_relative, False)
        self.assertEqual(relocations[8].type, lief.MachO.REBASE_TYPES.POINTER)
        self.assertEqual(relocations[8].section.name, "__mystuff")
        self.assertEqual(relocations[8].segment.name, "__DATA")

        self.assertEqual(relocations[9].address, 0x000012A8)
        self.assertEqual(relocations[9].pc_relative, False)
        self.assertEqual(relocations[9].type, lief.MachO.REBASE_TYPES.POINTER)
        self.assertEqual(relocations[9].section.name, "__mystuff")
        self.assertEqual(relocations[9].segment.name, "__DATA")


if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)

