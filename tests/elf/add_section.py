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
from utils import get_sample, has_recent_glibc, is_linux, is_x86_64, is_aarch64

CURRENT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))

STUB_FILE = None
if is_x86_64():
    STUB_FILE = "hello_lief.bin"
elif is_aarch64():
    STUB_FILE = "hello_lief_aarch64.bin"

STUB = lief.parse(os.path.join(CURRENT_DIRECTORY, STUB_FILE))

class TestAddSection(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.tmp_dir = tempfile.mkdtemp(suffix='_lief_test_section')
        self.logger.debug("temp dir: {}".format(self.tmp_dir))


    @unittest.skipUnless(is_linux() and is_x86_64(), "requires Linux x86-64")
    @unittest.skipUnless(has_recent_glibc(), "Need a recent GLIBC version")
    def test_simple(self):
        sample_path = get_sample('ELF/ELF64_x86-64_binary_ls.bin')
        output      = os.path.join(self.tmp_dir, "ls.section")

        ls = lief.parse(sample_path)
        for i in range(10):
            section = Section(".test.{:d}".format(i), lief.ELF.SECTION_TYPES.PROGBITS)
            section += lief.ELF.SECTION_FLAGS.EXECINSTR
            section += lief.ELF.SECTION_FLAGS.WRITE
            section.content   = STUB.segments[0].content # First LOAD segment which holds payload
            if i % 2 == 0:
                section = ls.add(section, loaded=True)
                ls.header.entrypoint = section.virtual_address + STUB.header.entrypoint
            else:
                section = ls.add(section, loaded=False)

        ls.write(output)

        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        p = Popen(output, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, _ = p.communicate()
        self.logger.debug(stdout.decode("utf8"))
        self.assertIsNotNone(re.search(r'LIEF is Working', stdout.decode("utf8")))


    @unittest.skipUnless(is_linux() and is_x86_64(), "requires Linux x86-64")
    @unittest.skipUnless(has_recent_glibc(), "Need a recent GLIBC version")
    def test_gcc(self):
        sample_path = get_sample('ELF/ELF64_x86-64_binary_gcc.bin')
        output      = os.path.join(self.tmp_dir, "gcc.section")

        gcc = lief.parse(sample_path)
        for i in range(10):
            section = Section(".test.{:d}".format(i), lief.ELF.SECTION_TYPES.PROGBITS)
            section.type     = lief.ELF.SECTION_TYPES.PROGBITS
            section         += lief.ELF.SECTION_FLAGS.EXECINSTR
            section         += lief.ELF.SECTION_FLAGS.WRITE
            section.content  = STUB.segments[0].content # First LOAD segment which holds payload

            if i % 2 == 0:
                section = gcc.add(section, loaded=True)
                gcc.header.entrypoint = section.virtual_address + STUB.header.entrypoint
            else:
                section = gcc.add(section, loaded=False)

        gcc.write(output)

        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        p = Popen(output, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, _ = p.communicate()
        self.logger.debug(stdout.decode("utf8"))
        self.assertIsNotNone(re.search(r'LIEF is Working', stdout.decode("utf8")))


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

