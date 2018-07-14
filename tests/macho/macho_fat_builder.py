#!/usr/bin/env python
import unittest
import lief
import tempfile
import logging
import os
from subprocess import Popen
import subprocess
import stat
import re
import sys

from unittest import TestCase
from utils import get_sample

from lief import Logger
Logger.set_level(lief.LOGGING_LEVEL.WARNING)

CURRENT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))

def run_program(path, args=None):
    # Make sure the program had exec permission
    st = os.stat(path)
    os.chmod(path, st.st_mode | stat.S_IEXEC)


    prog_args = path if not args else [path] + args
    p = Popen(prog_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout, _ = p.communicate()
    stdout = stdout.decode("utf8")
    return stdout

class TestMachOFatBuilder(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_all(self):
        original = lief.MachO.parse(get_sample('MachO/FAT_MachO_x86-x86-64-binary_fatall.bin'))
        self.assertEqual(len(original), 2)
        _, output = tempfile.mkstemp(prefix="lief_fatall_builder")
        original.write(output)


        if sys.platform.startswith("darwin"):
            stdout = run_program(output)
            self.logger.debug(stdout)
            self.assertIsNotNone(re.search(r'Hello World', stdout))



if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)

