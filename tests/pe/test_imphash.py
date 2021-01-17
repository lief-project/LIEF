#!/usr/bin/env python
# -*- coding: utf-8 -*-

import lief
import unittest
import logging
import os
import sys
import random

from unittest import TestCase
from utils import get_sample

class TestImphash(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)


    def test_without_imports(self):
        """
        By convention if a binary hasn't import, imphash is '0'
        """
        binary = lief.PE.Binary("test_imphash", lief.PE.PE_TYPE.PE32)

        self.assertEqual(int(lief.PE.get_imphash(binary), 16), 0)

    def test_casse(self):
        """
        Test that casse doesn't change the hash
        """
        binary_lhs = lief.PE.Binary("test_imphash_lhs", lief.PE.PE_TYPE.PE32)
        binary_rhs = lief.PE.Binary("test_imphash_rhs", lief.PE.PE_TYPE.PE32)

        kernel32_lhs = binary_lhs.add_library("KERNEL32.dll")
        kernel32_lhs.add_entry("CreateMutexA")

        kernel32_rhs = binary_rhs.add_library("kernel32.dll")
        kernel32_rhs.add_entry("CrEatEMutExa")

        self.assertEqual(lief.PE.get_imphash(binary_lhs), lief.PE.get_imphash(binary_rhs))


    def test_order(self):
        """
        Test that import order doesn't change the hash
        """
        binary_lhs = lief.PE.Binary("test_imphash_lhs", lief.PE.PE_TYPE.PE32)
        binary_rhs = lief.PE.Binary("test_imphash_rhs", lief.PE.PE_TYPE.PE32)
        fonctions = ["GetStringTypeW", "LCMapStringW", "GetCommandLineA", "TerminateProcess"]

        kernel32_lhs = binary_lhs.add_library("kernel32.dll")
        random.shuffle(fonctions)
        list(map(kernel32_lhs.add_entry, fonctions))
        self.logger.debug(kernel32_lhs)

        kernel32_rhs = binary_rhs.add_library("kernel32.dll")
        random.shuffle(fonctions)
        list(map(kernel32_rhs.add_entry, fonctions))
        self.logger.debug(kernel32_rhs)

        self.assertEqual(lief.PE.get_imphash(binary_lhs), lief.PE.get_imphash(binary_rhs))

    def test_ordinal(self):
        """
        Test import by ordinal
        """
        binary_lhs = lief.PE.Binary("test_imphash_lhs", lief.PE.PE_TYPE.PE32)
        binary_rhs = lief.PE.Binary("test_imphash_lhs", lief.PE.PE_TYPE.PE32)

        fonctions = [
                "GetStringTypeW",
                "LCMapStringW",
                "GetCommandLineA",
                "TerminateProcess",
                "Beep",
                "CheckRemoteDebuggerPresent",
                ]
        kernel32_lhs = binary_lhs.add_library("kernel32.dll")
        list(map(kernel32_lhs.add_entry, fonctions))

        kernel32_rhs = binary_rhs.add_library("kernel32.dll")
        for f in fonctions:
            if f == "Beep":
                imp = lief.PE.ImportEntry(0x8000001d) # Ordinal number
                kernel32_rhs.add_entry(imp)
            else:
                kernel32_rhs.add_entry(f)

        self.assertEqual(lief.PE.get_imphash(binary_lhs), lief.PE.get_imphash(binary_rhs))

    def test_order_2(self):
        """
        Test that import order doesn't change the hash (More complex)
        """
        binary_lhs = lief.PE.Binary("test_imphash_lhs", lief.PE.PE_TYPE.PE32)
        binary_rhs = lief.PE.Binary("test_imphash_rhs", lief.PE.PE_TYPE.PE32)


        libraries = {
                'KERNEL32.dll': [
                    "GetStringTypeW",
                    "LCMapStringW",
                    "GetCommandLineA",
                    "TerminateProcess",
                    "Beep",
                    "CheckRemoteDebuggerPresent",
                ],
                "ntdll.dll": [
                    "NtWriteVirtualMemory",
                    "NtYieldExecution",
                    "PfxFindPrefix",
                    "PfxInitialize",
                    "PfxInsertPrefix",
                    "PfxRemovePrefix",
                    "PropertyLengthAsVariant",
                    "RtlAbortRXact",
                ]
        }

        keys = list(libraries.keys())
        random.shuffle(keys)
        for k in keys:
            lib_lhs = binary_lhs.add_library(k)
            v = libraries[k]
            random.shuffle(v)
            for e in v:
                lib_lhs.add_entry(e)

        keys = list(libraries.keys())
        random.shuffle(keys)
        for k in keys:
            lib_rhs = binary_rhs.add_library(k)
            v = libraries[k]
            random.shuffle(v)
            for e in v:
                lib_rhs.add_entry(e)


        self.assertEqual(lief.PE.get_imphash(binary_lhs), lief.PE.get_imphash(binary_rhs))

    def test_different(self):
        """
        Check that different imports have different hashes
        """

        binary_lhs = lief.PE.Binary("test_imphash_lhs", lief.PE.PE_TYPE.PE32)
        binary_rhs = lief.PE.Binary("test_imphash_rhs", lief.PE.PE_TYPE.PE32)


        libraries = {
                'KERNEL32.dll': [
                    "GetStringTypeW",
                    "LCMapStringW",
                    "GetCommandLineA",
                    "TerminateProcess",
                    "Beep",
                    "CheckRemoteDebuggerPresent",
                ],
                "ntdll.dll": [
                    "NtWriteVirtualMemory",
                    "NtYieldExecution",
                    "PfxFindPrefix",
                    "PfxInitialize",
                    "PfxInsertPrefix",
                    "PfxRemovePrefix",
                    "PropertyLengthAsVariant",
                    "RtlAbortRXact",
                ]
        }

        keys = list(libraries.keys())
        random.shuffle(keys)
        for k in keys:
            lib_lhs = binary_lhs.add_library(k)
            v = libraries[k]
            random.shuffle(v)
            for e in v:
                lib_lhs.add_entry(e)

        keys = list(libraries.keys())
        random.shuffle(keys)
        for k in keys:
            lib_rhs = binary_rhs.add_library(k)
            v = libraries[k]
            random.shuffle(v)
            for e in filter(lambda e : len(e) % 2 == 0, v):
                lib_rhs.add_entry(e)


        self.assertNotEqual(lief.PE.get_imphash(binary_lhs), lief.PE.get_imphash(binary_rhs))


    def test_pefile(self):
        """
        Check that we can reproduce pefile output
        """
        s1 = lief.parse(get_sample("PE/PE64_x86-64_binary_notepad.exe"))
        self.assertEqual(lief.PE.get_imphash(s1, lief.PE.IMPHASH_MODE.PEFILE), "38934ee4aaaaa8dab7c73508bc6715ca")

        s2 = lief.parse(get_sample("PE/PE32_x86_binary_PGO-PGI.exe"))
        self.assertEqual(lief.PE.get_imphash(s2, lief.PE.IMPHASH_MODE.PEFILE), "4d7ac2eefa8a35d9c445d71412e8e71c")






if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)

