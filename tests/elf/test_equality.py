#!/usr/bin/env python
import itertools
import logging
import os
import random
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import TestCase

import lief
from utils import get_sample

lief.logging.set_level(lief.logging.LOGGING_LEVEL.INFO)

class TestEquality64(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.input = lief.parse(get_sample("ELF/ELF64_x86-64_binary_all.bin"))

        _, output = tempfile.mkstemp(prefix="all_bis")
        self.input.write(output)
        self.output = lief.parse(output)


    def test_header(self):
        self.assertEqual(self.input.header, self.output.header)

    def test_sections(self):
        for l, r in zip(self.input.sections, self.output.sections):
            self.assertEqual(l, r, "\n{!s}\n{!s}".format(l, r))

    def test_segments(self):
        for l, r in zip(self.input.segments, self.output.segments):
            self.assertEqual(l, r, "\n{!s}\n{!s}".format(l, r))

    def test_relocations(self):
        for l, r in zip(self.input.relocations, self.output.relocations):
            self.assertEqual(l, r, "\n{!s}\n{!s}".format(l, r))

    def test_symbols(self):
        for l, r in zip(self.input.symbols, self.output.symbols):
            self.assertEqual(l, r, "\n{!s}\n{!s}".format(l, r))

    def test_dynamic_entries(self):
        for l, r in zip(self.input.dynamic_entries, self.output.dynamic_entries):
            self.assertEqual(l, r, "\n{!s}\n{!s}".format(l, r))


class TestEquality32(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.input = lief.parse(get_sample("ELF/ELF32_x86_binary_all.bin"))

        _, output = tempfile.mkstemp(prefix="all_bis")
        print(output)
        self.input.write(output)
        self.output = lief.parse(output)


    def test_header(self):
        self.assertEqual(self.input.header, self.output.header)

    def test_sections(self):
        for l, r in zip(self.input.sections, self.output.sections):
            self.assertEqual(l, r, "\n{!s}\n{!s}".format(l, r))

    def test_segments(self):
        for l, r in zip(self.input.segments, self.output.segments):
            self.assertEqual(l, r, "\n{!s}\n{!s}".format(l, r))

    def test_relocations(self):
        for l, r in zip(self.input.relocations, self.output.relocations):
            self.assertEqual(l, r, "\n{!s}\n{!s}".format(l, r))

    def test_symbols(self):
        for l, r in zip(self.input.symbols, self.output.symbols):
            self.assertEqual(l, r, "\n{!s}\n{!s}".format(l, r))

    def test_dynamic_entries(self):
        for l, r in zip(self.input.dynamic_entries, self.output.dynamic_entries):
            self.assertEqual(l, r, "\n{!s}\n{!s}".format(l, r))

if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)
