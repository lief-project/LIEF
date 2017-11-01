#!/usr/bin/env python
import unittest
import lief
import logging
from io import open

from lief import Logger
Logger.set_level(lief.LOGGING_LEVEL.WARNING)

from unittest import TestCase
from utils import get_sample

class TestPythonApi(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_io(self):
        lspath = get_sample('ELF/ELF64_x86-64_binary_ls.bin')

        with open(lspath, 'r') as f:
            ls = lief.parse(f);
            self.assertIsNotNone(ls.abstract.header)


        with open(lspath, 'rb') as f:
            ls = lief.parse(f);
            self.assertIsNotNone(ls.abstract.header)


        with open(lspath, 'rb') as f:
            ls = lief.ELF.parse(f);
            self.assertIsNotNone(ls.abstract.header)

        with open(get_sample('PE/PE64_x86-64_binary_HelloWorld.exe'), 'rb') as f:
            binary = lief.PE.parse(f);
            self.assertIsNotNone(binary.abstract.header)

        with open(get_sample('MachO/MachO64_x86-64_binary_dd.bin'), 'rb') as f:
            binary = lief.MachO.parse(f)[0];
            self.assertIsNotNone(binary.abstract.header)



if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)

