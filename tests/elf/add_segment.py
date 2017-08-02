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

from unittest import TestCase
from utils import get_sample

CURRENT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
STUB = lief.parse(os.path.join(CURRENT_DIRECTORY, "hello_lief.bin"))

class TestAddSegment(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.tmp_dir = tempfile.mkdtemp(suffix='_lief_testhash')
        self.logger.debug("temp dir: {}".format(self.tmp_dir))


    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux")
    def test_simple(self):
        sample_path = get_sample('ELF/ELF64_x86-64_binary_ls.bin')
        output      = os.path.join(self.tmp_dir, "ls.segment")

        ls = lief.parse(sample_path)
        segment = Segment()
        segment.type      = lief.ELF.SEGMENT_TYPES.LOAD
        segment.flags     = lief.ELF.SEGMENT_FLAGS.R | lief.ELF.SEGMENT_FLAGS.W | lief.ELF.SEGMENT_FLAGS.X
        segment.content   = STUB.segments[0].content # First LOAD segment which holds payload
        segment.alignment = 8
        segment           = ls.add_segment(segment, base=0xA00000, force_note=True)

        ls.header.entrypoint = segment.virtual_address + STUB.header.entrypoint
        ls.write(output)

        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        p = Popen(output, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, _ = p.communicate()
        self.logger.debug(stdout.decode("utf8"))
        self.assertIsNotNone(re.search(r'LIEF is Working', stdout.decode("utf8")))


    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux")
    def test_gcc(self):
        sample_path = get_sample('ELF/ELF64_x86-64_binary_gcc.bin')
        output      = os.path.join(self.tmp_dir, "gcc.segment")

        gcc = lief.parse(sample_path)
        segment = Segment()
        segment.type      = lief.ELF.SEGMENT_TYPES.LOAD
        segment.flags     = lief.ELF.SEGMENT_FLAGS.R | lief.ELF.SEGMENT_FLAGS.W | lief.ELF.SEGMENT_FLAGS.X
        segment.content   = STUB.segments[0].content # First LOAD segment which holds payload
        segment.alignment = 8
        segment           = gcc.add_segment(segment, base=0xA00000, force_note=True)

        gcc.header.entrypoint = segment.virtual_address + STUB.header.entrypoint

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

