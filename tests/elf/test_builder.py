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

class TestBuilder(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_simple(self):
        binall = lief.parse(get_sample('ELF/ELF32_x86_binary_all.bin'))

    def test_sectionless(self):
        binall = lief.parse(get_sample('ELF/ELF64_x86-64_binary_rvs.bin'))

    def test_library(self):
        binall = lief.parse(get_sample('ELF/ELF64_x86-64_library_libadd.so'))

    def test_object(self):
        binall = lief.parse(get_sample('ELF/ELF64_x86-64_object_builder.o'))

    def test_android(self):
        binall = lief.parse(get_sample('ELF/ELF64_AArch64_piebinary_ndkr16.bin'))

    def test_corrupted(self):
        binall = lief.parse(get_sample('ELF/ELF32_x86_library_libshellx.so'))

    def test_gcc(self):
        binall = lief.parse(get_sample('ELF/ELF32_x86_binary_gcc.bin'))


if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)
