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
        output      = os.path.join(self.tmp_dir, "ls.segment")

        target                  = lief.parse(sample_path)
        for i in range(4):
            segment                 = stub.segments[0]
            original_va             = segment.virtual_address
            segment.virtual_address = 0
            segment                 = target.add(segment)
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
        output      = os.path.join(self.tmp_dir, "gcc.segment")

        target                  = lief.parse(sample_path)
        segment                 = stub.segments[0]
        original_va             = segment.virtual_address
        segment.virtual_address = 0
        segment                 = target.add(segment)
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
    def test_static(self):
        sample_path = get_sample('ELF/ELF64_x86-64_binary_static-binary.bin')
        stub        = lief.parse(os.path.join(CURRENT_DIRECTORY, "hello_lief.bin"))
        output      = os.path.join(self.tmp_dir, "static.segment")

        target                  = lief.parse(sample_path)
        segment                 = stub.segments[0]
        original_va             = segment.virtual_address
        segment.virtual_address = 0
        segment                 = target.add(segment)
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
    def test_misc(self):
        list_binaries = [
        '/usr/bin/ls',
        '/usr/bin/ssh',
        '/usr/bin/nm',
        '/usr/bin/openssl',
        '/usr/bin/bc',
        '/usr/bin/bzip2',
        '/usr/bin/cp',
        '/usr/bin/find',
        '/usr/bin/file',
        ]
        for binary in list_binaries:
            self.logger.debug("Test with '{}'".format(binary))
            self.run_add_segment(binary)


    def run_add_segment(self, target):
        if not os.path.isfile(target):
            return

        name   = os.path.basename(target)
        stub   = lief.parse(os.path.join(CURRENT_DIRECTORY, "hello_lief.bin"))
        target = lief.parse(target)
        output = os.path.join(self.tmp_dir, "{}.segment".format(name))
        for i in range(6):
            segment                 = stub.segments[0]
            original_va             = segment.virtual_address
            segment.virtual_address = 0
            segment                 = target.add(segment)
            new_ep                  = (stub.header.entrypoint - original_va) + segment.virtual_address

            target.header.entrypoint = new_ep
        target.write(output)

        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        p = Popen(output, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, _ = p.communicate()
        self.logger.debug(stdout.decode("utf8"))
        self.assertIsNotNone(re.search(r'LIEF is Working', stdout.decode("utf8")))

    @unittest.skipUnless(False, "requires Linux")
    def test_libc(self):
        stub = lief.parse(os.path.join(CURRENT_DIRECTORY, "hello_lief.bin"))
        tmp_dir = tempfile.mkdtemp(suffix='_lief_test_add_segment_libc')
        self.logger.debug("temp dir: {}".format(tmp_dir))

        libc_name = "libc.so.6"
        for e in lief.parse("/bin/ls").libraries:
            if e.startswith("libc."):
                libc_name = e
                break;

        self.logger.debug("libc used: {}".format(libc_name))


        libc = lief.parse('/usr/lib/{}'.format(libc_name))
        out = os.path.join(tmp_dir, libc_name)

        for i in range(10):
            segment = stub.segments[0]
            original_va = segment.virtual_address
            segment.virtual_address = 0

            segment = libc.add(segment)

            new_ep = (stub.header.entrypoint - original_va) + segment.virtual_address

            if libc.has(lief.ELF.DYNAMIC_TAGS.INIT_ARRAY):
                init_array = libc.get(lief.ELF.DYNAMIC_TAGS.INIT_ARRAY)
                callbacks = init_array.array
                callbacks[0] = new_ep
                init_array.array = callbacks

            if libc.has(lief.ELF.DYNAMIC_TAGS.INIT):
                init = libc.get(lief.ELF.DYNAMIC_TAGS.INIT)
                init.value = new_ep

        libc.write(out)

        st = os.stat(out)
        os.chmod(out, st.st_mode | stat.S_IEXEC)

        p = Popen(["/usr/bin/ls"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env={"LD_LIBRARY_PATH": tmp_dir})
        stdout, _ = p.communicate()
        self.logger.debug(stdout.decode("utf8"))

        self.assertIsNotNone(re.search(r'LIEF is Working', stdout.decode("utf8")))

        if os.path.isdir(tmp_dir):
            shutil.rmtree(tmp_dir)




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

