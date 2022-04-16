#!/usr/bin/env python
import lief
import os
import pathlib

from utils import get_sample

CURRENT_DIR = pathlib.Path(__file__).parent

def read_opcode_file(name):
    buff = (CURRENT_DIR / "opcodes" / name).read_text()
    buff = buff.replace("\r", "")
    return buff

def test_rebase_opcodes():
    target = lief.parse(get_sample("MachO/MachO64_x86-64_binary_rebase-LLVM.bin"))

    reference = read_opcode_file("MachO64_x86-64_binary_rebase-LLVM.rebase_opcodes")
    value = target.dyld_info.show_rebases_opcodes
    value = value.replace("\r", "")
    assert reference == value

def test_lazy_bind_opcodes():
    target = lief.parse(get_sample("MachO/MachO64_x86-64_binary_lazy-bind-LLVM.bin"))

    reference = read_opcode_file("MachO64_x86-64_binary_lazy-bind-LLVM.lazy_bind_opcodes")
    value = target.dyld_info.show_lazy_bind_opcodes
    value = value.replace("\r", "")
    assert reference == value

def test_bind_opcodes():
    target = lief.parse(get_sample("MachO/MachO64_x86-64_binary_lazy-bind-LLVM.bin"))

    reference = read_opcode_file("MachO64_x86-64_binary_lazy-bind-LLVM.bind_opcodes")
    value = target.dyld_info.show_bind_opcodes
    value = value.replace("\r", "")
    assert reference == value

def test_export_trie():
    target = lief.parse(get_sample("MachO/MachO64_x86-64_binary_lazy-bind-LLVM.bin"))

    reference = read_opcode_file("MachO64_x86-64_binary_lazy-bind-LLVM.export_trie")
    value = target.dyld_info.show_export_trie
    value = value.replace("\r", "")

    assert reference == value

