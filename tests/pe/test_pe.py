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
import re

from subprocess import Popen

from unittest import TestCase
from utils import get_sample

class TestPe(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.maxDiff = None

        self.tmp_dir = tempfile.mkdtemp(suffix='_lief_tests')
        self.logger.debug("temp dir: {}".format(self.tmp_dir))


        if sys.platform.startswith("win"):
            SEM_NOGPFAULTERRORBOX = 0x0002 # From MSDN
            ctypes.windll.kernel32.SetErrorMode(SEM_NOGPFAULTERRORBOX);


    def test_code_view_pdb(self):
        path = get_sample('PE/PE64_x86-64_binary_ConsoleApplication1.exe')
        sample = lief.parse(path)

        self.assertTrue(sample.has_debug)

        debug_code_view = list(filter(lambda deb: deb.has_code_view, sample.debug))
        self.assertTrue(len(debug_code_view) == 1)

        debug = debug_code_view[0]
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

    def test_remove_section(self):
        path = get_sample('PE/PE64_x86-64_remove_section.exe')
        sample = lief.parse(path)

        output = os.path.join(self.tmp_dir, "section_removed.exe")

        sample.remove_section("lief")
        sample.write(output)

        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        if sys.platform.startswith("win"):
            subprocess_flags = 0x8000000 # win32con.CREATE_NO_WINDOW?
            p = Popen([output], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=subprocess_flags)

            stdout, _ = p.communicate()
            stdout = stdout.decode("utf8")
            self.logger.debug(stdout)
            self.assertIn("Hello World", stdout)

    def test_unwind(self):

        path = get_sample("PE/PE64_x86-64_binary_cmd.exe")
        sample = lief.parse(path)

        functions = sorted(sample.functions, key=lambda f: f.address)

        self.assertEqual(len(functions), 829)

        self.assertEqual(functions[0].address, 4160)
        self.assertEqual(functions[0].size,    107)
        self.assertEqual(functions[0].name,    "")

        self.assertEqual(functions[-1].address, 163896)
        self.assertEqual(functions[-1].size,    54)
        self.assertEqual(functions[-1].name,    "")

    def test_pgo(self):
        path   = get_sample("PE/PE32_x86_binary_PGO-LTCG.exe")
        sample = lief.parse(path)

        debugs = sample.debug
        self.assertEqual(len(debugs), 3)

        debug_entry = debugs[2]

        self.assertTrue(debug_entry.has_pogo)
        pogo = debug_entry.pogo
        self.assertEqual(pogo.signature, lief.PE.POGO_SIGNATURES.LCTG)

        pogo_entries = pogo.entries
        self.assertEqual(len(pogo_entries), 33)

        self.assertEqual(pogo_entries[23].name,      ".xdata$x")
        self.assertEqual(pogo_entries[23].start_rva, 0x8200)
        self.assertEqual(pogo_entries[23].size,      820)


    def test_sections(self):
        path = get_sample("PE/PE32_x86_binary_PGO-LTCG.exe")
        pe = lief.parse(path)
        self.assertIsNotNone(pe.get_section(".text"))
        self.assertEqual(pe.sections[0].name, ".text")
        self.assertEqual(pe.sections[0].fullname.encode("utf8"), b".text\x00\x00\x00")

    def tearDown(self):
        # Delete it
        try:
            if os.path.isdir(self.tmp_dir):
                shutil.rmtree(self.tmp_dir)
        except Exception as e:
            self.logger.error(e)

if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)

