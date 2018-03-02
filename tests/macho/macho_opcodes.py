#!/usr/bin/env python
import unittest
import lief
import logging
import os
import io

from unittest import TestCase
from utils import get_sample

CURRENT_DIR = os.path.abspath(os.path.dirname(__file__))

def read_opcode_file(name):
    buff = None
    with open(os.path.join(CURRENT_DIR, "opcodes", name), 'r') as f:
        buff = f.read()
    buff = buff.replace("\r", "")
    return buff

class TestMachOOpcodes(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.maxDiff = None

    def test_rebase_opcodes(self):
        target = lief.parse(get_sample("MachO/MachO64_x86-64_binary_rebase-LLVM.bin"))

        reference = read_opcode_file("MachO64_x86-64_binary_rebase-LLVM.rebase_opcodes")
        value = target.dyld_info.show_rebases_opcodes
        value = value.replace("\r", "")
        self.assertMultiLineEqual(reference, value)

    def test_lazy_bind_opcodes(self):
        target = lief.parse(get_sample("MachO/MachO64_x86-64_binary_lazy-bind-LLVM.bin"))

        reference = read_opcode_file("MachO64_x86-64_binary_lazy-bind-LLVM.lazy_bind_opcodes")
        value = target.dyld_info.show_lazy_bind_opcodes
        value = value.replace("\r", "")
        self.assertMultiLineEqual(reference, value)

    def test_bind_opcodes(self):
        target = lief.parse(get_sample("MachO/MachO64_x86-64_binary_lazy-bind-LLVM.bin"))

        reference = read_opcode_file("MachO64_x86-64_binary_lazy-bind-LLVM.bind_opcodes")
        value = target.dyld_info.show_bind_opcodes
        value = value.replace("\r", "")
        self.assertMultiLineEqual(reference, value)

    def test_export_trie(self):
        target = lief.parse(get_sample("MachO/MachO64_x86-64_binary_lazy-bind-LLVM.bin"))

        reference = read_opcode_file("MachO64_x86-64_binary_lazy-bind-LLVM.export_trie")
        value = target.dyld_info.show_export_trie
        value = value.replace("\r", "")
        self.assertMultiLineEqual(reference, value)




if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)
