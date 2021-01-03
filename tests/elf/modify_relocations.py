#!/usr/bin/env python
import unittest
import logging
import os
import sys
import stat
import re
import subprocess
import tempfile
import shutil
from subprocess import Popen

import lief
from lief.ELF import Section

from unittest import TestCase
from utils import get_sample, has_recent_glibc, is_linux, is_x86_64

class TestRelocations(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.tmp_dir = tempfile.mkdtemp(suffix='_lief_test_relocations')
        self.logger.debug("temp dir: {}".format(self.tmp_dir))


    @unittest.skipUnless(is_linux() and is_x86_64(), "requires Linux x86-64")
    @unittest.skipUnless(has_recent_glibc(), "Need a recent GLIBC version")
    def test_simple(self):
        sample_path = get_sample('ELF/ELF64_x86-64_binary_ls.bin')
        output      = os.path.join(self.tmp_dir, "ls.relocation")

        ls = lief.parse(sample_path)

        relocation = lief.ELF.Relocation(0x61D370, type=lief.ELF.RELOCATION_X86_64.JUMP_SLOT, is_rela=True)

        symbol = lief.ELF.Symbol()
        symbol.name = "printf123"

        relocation.symbol = symbol

        ls.add_pltgot_relocation(relocation)

        ls.write(output)

        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        p = Popen([output, "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, _ = p.communicate()
        self.logger.debug(stdout.decode("utf8"))
        self.assertIsNotNone(re.search(r'ls \(GNU coreutils\) ', stdout.decode("utf8")))

    @unittest.skipUnless(is_linux() and is_x86_64(), "requires Linux x86-64")
    def test_all(self):
        sample_path = get_sample('ELF/ELF64_x86-64_binary_all.bin')
        output      = os.path.join(self.tmp_dir, "all.relocation")

        target = lief.parse(sample_path)

        relocation = lief.ELF.Relocation(0x201028, type=lief.ELF.RELOCATION_X86_64.JUMP_SLOT, is_rela=True)

        symbol = lief.ELF.Symbol()
        symbol.name = "printf123"

        relocation.symbol = symbol
        target.add_pltgot_relocation(relocation)

        target.write(output)

        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        p = Popen([output], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, _ = p.communicate()
        self.logger.debug(stdout.decode("utf8"))
        self.assertIsNotNone(re.search(r'Hello World: 1', stdout.decode("utf8")))


    @unittest.skipUnless(is_linux() and is_x86_64(), "requires Linux x86-64")
    def test_all32(self):
        sample_path = get_sample('ELF/ELF32_x86_binary_all.bin')
        output      = os.path.join(self.tmp_dir, "all32.relocation")

        target = lief.parse(sample_path)

        relocation = lief.ELF.Relocation(0x2018, type=lief.ELF.RELOCATION_i386.JUMP_SLOT, is_rela=False)

        symbol = lief.ELF.Symbol()
        symbol.name = "printf123"

        relocation.symbol = symbol
        target.add_pltgot_relocation(relocation)

        target.write(output)

        new = lief.parse(output)
        self.assertTrue(new.has_symbol("printf123"))

        #st = os.stat(output)
        #os.chmod(output, st.st_mode | stat.S_IEXEC)

        #p = Popen([output], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        #stdout, _ = p.communicate()
        #self.logger.debug(stdout.decode("utf8"))
        #self.assertIsNotNone(re.search(r'Hello World: 1', stdout.decode("utf8")))



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

