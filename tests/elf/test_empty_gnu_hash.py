#!/usr/bin/env python
import unittest
import logging
import os
import sys
import platform
import stat
import re
import subprocess
import tempfile
import shutil
from subprocess import Popen
import ctypes
import lief

from unittest import TestCase
from utils import get_sample, has_recent_glibc, is_linux, is_x86_64

class TestEmptyGNUHash(TestCase):
    SYMBOLS = {
        "myinstance": 0x1159,
        "myinit":     0x1175,
        "mycalc":     0x1199,
        "mydelete":   0x1214,
    }

    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.tmp_dir = tempfile.mkdtemp(suffix='_lief_test_empty_gnu_hash')
        self.logger.debug("temp dir: {}".format(self.tmp_dir))


    @unittest.skipUnless(is_linux() and is_x86_64(), "requires Linux x86-64")
    @unittest.skipUnless(has_recent_glibc(), "Need a recent GLIBC version")
    def test_export(self):
        target_path = get_sample('ELF/ELF64_x86-64_binary_empty-gnu-hash.bin')
        output      = os.path.join(self.tmp_dir, "libnoempty.so")

        binary = lief.parse(target_path)

        binary[lief.ELF.DYNAMIC_TAGS.FLAGS_1].remove(lief.ELF.DYNAMIC_FLAGS_1.PIE)

        for name, addr in TestEmptyGNUHash.SYMBOLS.items():
            binary.add_exported_function(addr, name)
        binary.write(output)

        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        lib = ctypes.cdll.LoadLibrary(output)
        # Raise 'AttributeError' if not exported
        print(lib.myinstance)
        self.assertIsNotNone(lib.myinstance)

    def tearDown(self):
        # Delete it
        if os.path.isdir(self.tmp_dir):
            shutil.rmtree(self.tmp_dir)

if __name__ == '__main__':
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)

