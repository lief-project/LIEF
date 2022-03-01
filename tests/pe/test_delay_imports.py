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

class TestDelayImport(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_simple(self):
        """
        Referential test on a simple case
        This test aims at checking we cover correctly a regular binary
        """
        binary: lief.PE.Binary = lief.parse(get_sample("PE/test.delay.exe"))

        self.assertEqual(binary.has_delay_imports, True)
        self.assertEqual(len(binary.delay_imports), 2)
        self.assertIsNot(binary.get_delay_import("USER32.dll"), None)
        self.assertEqual(binary.has_delay_import("USER32.dll"), True)

        # Check that took care of updating the abstract layer
        self.assertEqual(len(binary.imported_functions), 87)
        self.assertEqual(len(binary.libraries), 3)

        # Now check in depth the delay imports
        shlwapi = binary.delay_imports[0]
        self.assertEqual(shlwapi.name,         "SHLWAPI.dll")
        self.assertEqual(shlwapi.attribute,    1)
        self.assertEqual(shlwapi.handle,       0x29dc8)
        self.assertEqual(shlwapi.iat,          0x25d30)
        self.assertEqual(shlwapi.names_table,  0x23f48)
        self.assertEqual(shlwapi.biat,         0x23f80)
        self.assertEqual(shlwapi.uiat,         0)
        self.assertEqual(shlwapi.timestamp,    0)
        self.assertEqual(len(shlwapi.entries), 1)

        strstra = shlwapi.entries[0]

        self.assertEqual(strstra.name,      "StrStrA")
        self.assertEqual(strstra.value,     0x00025d30)
        self.assertEqual(strstra.iat_value, 0x0300905a4d)
        self.assertEqual(strstra.data,      0x23f68)
        self.assertEqual(strstra.hint,      0x14d)

        user32 = binary.delay_imports[1]
        self.assertEqual(user32.name,         "USER32.dll")
        self.assertEqual(user32.attribute,    1)
        self.assertEqual(user32.handle,       0x29dd0)
        self.assertEqual(user32.iat,          0x25d40)
        self.assertEqual(user32.names_table,  0x23f58)
        self.assertEqual(user32.biat,         0x23f90)
        self.assertEqual(user32.uiat,         0)
        self.assertEqual(user32.timestamp,    0)
        self.assertEqual(len(user32.entries), 1)

        messageboxa = user32.entries[0]

        self.assertEqual(messageboxa.name,      "MessageBoxA")
        self.assertEqual(messageboxa.value,     0x25d40)
        self.assertEqual(messageboxa.iat_value, 0x0300905a4d)
        self.assertEqual(messageboxa.data,      0x23f72)
        self.assertEqual(messageboxa.hint,      0x285)

    def test_cmd(self):
        """
        Test on cmd.exe
        """
        binary: lief.PE.Binary = lief.parse(get_sample("PE/PE64_x86-64_binary_cmd.exe"))

        self.assertEqual(binary.has_delay_imports, True)
        self.assertEqual(len(binary.delay_imports), 4)

        self.assertEqual(len(binary.imported_functions), 247)
        self.assertEqual(len(binary.libraries), 8)

        shell32 = binary.get_delay_import("SHELL32.dll")
        self.assertEqual(shell32.name,         "SHELL32.dll")
        self.assertEqual(shell32.attribute,    1)
        self.assertEqual(shell32.handle,       0x2e2e8)
        self.assertEqual(shell32.iat,          0x2e078)
        self.assertEqual(shell32.names_table,  0x2a5a0)
        self.assertEqual(shell32.biat,         0)
        self.assertEqual(shell32.uiat,         0)
        self.assertEqual(shell32.timestamp,    0)
        self.assertEqual(len(shell32.entries), 2)

        SHChangeNotify = shell32.entries[0]

        self.assertEqual(SHChangeNotify.name,      "SHChangeNotify")
        self.assertEqual(SHChangeNotify.value,     0x0002e078)
        self.assertEqual(SHChangeNotify.iat_value, 0x0300905a4d)
        self.assertEqual(SHChangeNotify.data,      0x2a6ee)
        self.assertEqual(SHChangeNotify.hint,      0)

        ShellExecuteExW = shell32.entries[1]

        self.assertEqual(ShellExecuteExW.name,      "ShellExecuteExW")
        self.assertEqual(ShellExecuteExW.value,     0x0002e080)
        self.assertEqual(ShellExecuteExW.iat_value, 0xffff00000004)
        self.assertEqual(ShellExecuteExW.data,      0x2a700)
        self.assertEqual(ShellExecuteExW.hint,      0)


if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)

