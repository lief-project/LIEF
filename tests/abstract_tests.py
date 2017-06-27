#!/usr/bin/env python
import unittest
import lief
import tempfile
import sys
import subprocess
import stat
import os
import logging
import random

from subprocess import Popen

from unittest import TestCase
from utils import get_sample

class TestAbstract(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_endianness(self):
        binary = lief.parse(get_sample('ELF/ELF32_x86_binary_ls.bin'))
        binary = super(binary.__class__, binary)
        header = binary.header

        self.assertEqual(header.endianness, lief.ENDIANNESS.LITTLE)


        binary = lief.parse(get_sample('MachO/MachO64_x86-64_binary_id.bin'))
        binary = super(binary.__class__, binary)
        header = binary.header

        self.assertEqual(header.endianness, lief.ENDIANNESS.LITTLE)


        binary = lief.parse(get_sample('PE/PE64_x86-64_binary_ConsoleApplication1.exe'))
        binary = super(binary.__class__, binary)
        header = binary.header

        self.assertEqual(header.endianness, lief.ENDIANNESS.LITTLE)


if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)

