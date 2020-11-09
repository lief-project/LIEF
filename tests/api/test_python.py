#!/usr/bin/env python
import io
import logging
import unittest
from io import open as io_open
from unittest import TestCase

import lief
from utils import get_sample

lief.logging.set_level(lief.logging.LOGGING_LEVEL.INFO)

class TestPythonApi(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_io(self):
        lspath = get_sample('ELF/ELF64_x86-64_binary_ls.bin')

        ls = lief.parse(lspath)
        self.assertIsNotNone(ls.abstract.header)

        with io_open(lspath, 'r') as f:
            ls = lief.parse(f)
            self.assertIsNotNone(ls.abstract.header)

        with io_open(lspath, 'rb') as f:
            ls = lief.parse(f)
            self.assertIsNotNone(ls.abstract.header)

        with io_open(lspath, 'rb') as f:
            ls = lief.ELF.parse(f)
            self.assertIsNotNone(ls.abstract.header)

        with io_open(get_sample('PE/PE64_x86-64_binary_HelloWorld.exe'), 'rb') as f:
            binary = lief.PE.parse(f)
            self.assertIsNotNone(binary.abstract.header)

        with io_open(get_sample('MachO/MachO64_x86-64_binary_dd.bin'), 'rb') as f:
            binary = lief.MachO.parse(f)[0]
            self.assertIsNotNone(binary.abstract.header)

        with open(lspath, 'rb') as f:  # As bytes
            ls = lief.parse(f.read())
            self.assertIsNotNone(ls.abstract.header)

        with open(lspath, 'rb') as f:  # As io.BufferedReader
            ls = lief.parse(f)
            self.assertIsNotNone(ls.abstract.header)

        with open(lspath, 'rb') as f:  # As io.BytesIO object
            bytes_stream = io.BytesIO(f.read())
            self.assertIsNotNone(bytes_stream)


if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)
