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
from lief.ELF import Segment
from lief import Logger
#Logger.set_level(lief.LOGGING_LEVEL.DEBUG)

from unittest import TestCase
from utils import get_sample

CURRENT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class TestAddSegment(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.tmp_dir = tempfile.mkdtemp(suffix='_lief_test_add_segment')
        self.logger.debug("temp dir: {}".format(self.tmp_dir))


    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux")
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


    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux")
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


    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux")
    def test_ssh(self):
        stub        = lief.parse(os.path.join(CURRENT_DIRECTORY, "hello_lief.bin"))
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

