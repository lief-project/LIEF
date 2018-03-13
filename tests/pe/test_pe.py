#!/usr/bin/env python
# -*- coding: utf-8 -*-

import lief
import unittest
import logging
import tempfile
import shutil
import os
import sys
import stat
import subprocess
import time
import ctypes
import zipfile
import json

from subprocess import Popen

from unittest import TestCase
from utils import get_sample

class TestPe(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.maxDiff = None


    def test_code_view_pdb(self):
        path = get_sample('PE/PE64_x86-64_binary_ConsoleApplication1.exe')
        sample = lief.parse(path)

        self.assertTrue(sample.has_debug)

        debug = sample.debug

        self.assertTrue(debug.has_code_view)

        code_view = debug.code_view

        self.assertEqual(code_view.cv_signature, lief.PE.CODE_VIEW_SIGNATURES.PDB_70)
        self.assertEqual(code_view.signature, [245, 217, 227, 182, 71, 113, 1, 79, 162, 3, 170, 71, 124, 74, 186, 84])
        self.assertEqual(code_view.age, 1)
        self.assertEqual(code_view.filename, r"c:\users\romain\documents\visual studio 2015\Projects\HelloWorld\x64\Release\ConsoleApplication1.pdb")

        json_view = json.loads(lief.to_json(debug))
        self.assertDictEqual(json_view, {
            'addressof_rawdata': 8996,
            'characteristics': 0,
            'code_view': {
                'age': 1,
                'cv_signature': 'PDB_70',
                'filename': 'c:\\users\\romain\\documents\\visual studio 2015\\Projects\\HelloWorld\\x64\\Release\\ConsoleApplication1.pdb',
                'signature': [245, 217, 227, 182, 71, 113, 1, 79, 162, 3, 170, 71, 124, 74, 186, 84]
            },
            'major_version': 0,
            'minor_version': 0,
            'pointerto_rawdata': 5412,
            'sizeof_data': 125,
            'timestamp': 1459952944,
            'type': 'CODEVIEW'
        })




if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)

