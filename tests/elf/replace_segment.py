#!/usr/bin/env python
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from subprocess import Popen
from unittest import TestCase

import lief
from lief.ELF import Segment
from utils import get_sample, has_recent_glibc, is_linux, is_x86_64, is_aarch64

lief.logging.set_level(lief.logging.LOGGING_LEVEL.INFO)

CURRENT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class TestAddSegment(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.tmp_dir = tempfile.mkdtemp(suffix='_lief_test_add_segment')
        self.logger.debug("temp dir: {}".format(self.tmp_dir))


    @unittest.skipUnless(is_linux() and is_x86_64(), "requires Linux x86-64")
    @unittest.skipUnless(has_recent_glibc(), "Need a recent GLIBC version")
    def test_simple(self):
        sample_path = get_sample('ELF/ELF64_x86-64_binary_ls.bin')
        stub        = lief.parse(os.path.join(CURRENT_DIRECTORY, "hello_lief.bin"))
        output      = os.path.join(self.tmp_dir, "ls.replace_segment")
        target      = lief.parse(sample_path)


        if not lief.ELF.SEGMENT_TYPES.NOTE in target:
            self.logger.error("Note not found!")
            return

        segment                 = stub.segments[0]
        original_va             = segment.virtual_address
        segment.virtual_address = 0
        segment                 = target.replace(segment, target[lief.ELF.SEGMENT_TYPES.NOTE])
        new_ep                  = (stub.header.entrypoint - original_va) + segment.virtual_address

        target.header.entrypoint = new_ep
        target.write(output)

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
        stub        = lief.parse(os.path.join(CURRENT_DIRECTORY, "hello_lief.bin"))
        output      = os.path.join(self.tmp_dir, "gcc.replace_segment")
        target      = lief.parse(sample_path)


        if not lief.ELF.SEGMENT_TYPES.NOTE in target:
            self.logger.error("Note not found!")
            return

        segment                 = stub.segments[0]
        original_va             = segment.virtual_address
        segment.virtual_address = 0
        segment                 = target.replace(segment, target[lief.ELF.SEGMENT_TYPES.NOTE])
        new_ep                  = (stub.header.entrypoint - original_va) + segment.virtual_address

        target.header.entrypoint = new_ep
        target.write(output)

        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        p = Popen(output, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, _ = p.communicate()
        self.logger.debug(stdout.decode("utf8"))
        self.assertIsNotNone(re.search(r'LIEF is Working', stdout.decode("utf8")))


    @unittest.skipUnless(is_linux(), "requires Linux")
    @unittest.skipUnless(has_recent_glibc(), "Need a recent GLIBC version")
    def test_ssh(self):
        stub = None
        if is_x86_64():
            stub = lief.parse(os.path.join(CURRENT_DIRECTORY, "hello_lief.bin"))
        elif is_aarch64():
            stub = lief.parse(os.path.join(CURRENT_DIRECTORY, "hello_lief_aarch64.bin"))

        output      = os.path.join(self.tmp_dir, "ssh.replace_segment")
        target      = lief.parse("/usr/bin/ssh")

        if not lief.ELF.SEGMENT_TYPES.NOTE in target:
            self.logger.error("Note not found!")
            return

        segment                 = stub.segments[0]
        original_va             = segment.virtual_address
        segment.virtual_address = 0
        segment                 = target.replace(segment, target[lief.ELF.SEGMENT_TYPES.NOTE])
        new_ep                  = (stub.header.entrypoint - original_va) + segment.virtual_address

        target.header.entrypoint = new_ep
        target.write(output)

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
