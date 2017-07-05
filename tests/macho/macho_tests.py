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
import itertools

from subprocess import Popen

from unittest import TestCase
from utils import get_sample

class TestMachO(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_function_starts(self):
        dd = lief.parse(get_sample('MachO/MachO64_x86-64_binary_dd.bin'))

        functions = [
            0x100001581, 0x1000016cc, 0x1000017cc,
            0x1000019e3, 0x100001a03, 0x100001a1d,
            0x1000020ad, 0x1000022f6, 0x1000023ef,
	    0x10000246b, 0x10000248c, 0x1000026da,
            0x100002754, 0x10000286b, 0x100002914,
	    0x100002bd8, 0x100002be8, 0x100002c2b,
	    0x100002c62, 0x100002d24, 0x100002d5a,
	    0x100002d91, 0x100002dd5, 0x100002de6,
	    0x100002dfc, 0x100002e40, 0x100002e51,
	    0x100002e67, 0x100002f9e
        ]

        self.assertEqual(dd.function_starts.data_offset, 21168)
        self.assertEqual(dd.function_starts.data_size,   48)
        text_segment = list(filter(lambda e : e.name == "__TEXT", dd.segments))[0]
        functions_dd = map(text_segment.virtual_address .__add__, dd.function_starts.functions)

        self.assertEqual(functions, list(functions_dd))

if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)

