#!/usr/bin/env python
import unittest
import lief # type: ignore
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
from utils import get_sample # type: ignore


class TestRelocation(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_object_relocations(self):
        #lief.logging.set_level(lief.logging.LOGGING_LEVEL.DEBUG)
        json_api = lief.parse(get_sample('MachO/json_api.cpp_1.o'))
        self.assertEqual(len(json_api.sections), 8)

        self.assertEqual(json_api.sections[0].segment_name, "__TEXT")
        self.assertEqual(json_api.sections[1].segment_name, "__TEXT")
        self.assertEqual(json_api.sections[2].segment_name, "__TEXT")
        self.assertEqual(json_api.sections[3].segment_name, "__TEXT")
        self.assertEqual(json_api.sections[4].segment_name, "__TEXT")
        self.assertEqual(json_api.sections[5].segment_name, "__DATA")
        self.assertEqual(json_api.sections[6].segment_name, "__LD")
        self.assertEqual(json_api.sections[7].segment_name, "__TEXT")

        self.assertEqual(json_api.sections[0].name, "__text")
        self.assertEqual(json_api.sections[1].name, "__gcc_except_tab")
        self.assertEqual(json_api.sections[2].name, "__literal16")
        self.assertEqual(json_api.sections[3].name, "__const")
        self.assertEqual(json_api.sections[4].name, "__cstring")
        self.assertEqual(json_api.sections[5].name, "__const")
        self.assertEqual(json_api.sections[6].name, "__compact_unwind")
        self.assertEqual(json_api.sections[7].name, "__eh_frame")

        self.assertEqual(len(json_api.sections[0].relocations), 381)
        self.assertEqual(len(json_api.sections[1].relocations), 0)
        self.assertEqual(len(json_api.sections[2].relocations), 0)
        self.assertEqual(len(json_api.sections[3].relocations), 0)
        self.assertEqual(len(json_api.sections[4].relocations), 0)
        self.assertEqual(len(json_api.sections[5].relocations), 186)
        self.assertEqual(len(json_api.sections[6].relocations), 186)
        self.assertEqual(len(json_api.sections[7].relocations), 399)
if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)

