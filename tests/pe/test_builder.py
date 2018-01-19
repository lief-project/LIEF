#!/usr/bin/env python
# -*- coding: utf-8 -*-

import lief
import unittest
import logging
import os
import sys
import stat
import re
import subprocess
import tempfile
import shutil
import time
import ctypes
import zipfile

from subprocess import Popen

from unittest import TestCase
from utils import get_sample

class TestBuilder(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.tmp_dir = tempfile.mkdtemp(suffix='_lief_test_builder')
        self.logger.debug("temp dir: {}".format(self.tmp_dir))

        if sys.platform.startswith("win"):
            SEM_NOGPFAULTERRORBOX = 0x0002 # From MSDN
            ctypes.windll.kernel32.SetErrorMode(SEM_NOGPFAULTERRORBOX);

    def test_add_multiples_sections(self):
        sample_file = get_sample('PE/PE32_x86_binary_Notepad++.zip')
        sample_dir  = os.path.join(self.tmp_dir, "Notepad++")

        sample = os.path.join(sample_dir, "notepad++.exe")
        output = os.path.join(sample_dir, "notepad++_sections.exe")

        zip_ref = zipfile.ZipFile(sample_file, 'r')
        zip_ref.extractall(self.tmp_dir)
        zip_ref.close()

        notepadpp = lief.parse(sample)

        # Add 20 sections to the binary
        for i in range(20):
            section = lief.PE.Section(".section_{}".format(i))
            section.content = [i & 0xFF for i in range(0x200)]
            notepadpp.add_section(section)

        builder = lief.PE.Builder(notepadpp)
        builder.build()

        builder.write(output)

        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        if sys.platform.startswith("win"):
            subprocess_flags = 0x8000000 # win32con.CREATE_NO_WINDOW?
            p = Popen(["START", output], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=subprocess_flags)
            time.sleep(3)
            q = Popen(["taskkill", "/im", "notepad++_sections.exe"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

            stdout, _ = p.communicate()
            self.logger.debug(stdout.decode("utf8"))

            stdout, _ = q.communicate()
            self.logger.debug(stdout.decode("utf8"))

            self.assertEqual(q.returncode, 0)


    def test_imports_notepadpp(self):
        sample_file = get_sample('PE/PE32_x86_binary_Notepad++.zip')
        sample_dir  = os.path.join(self.tmp_dir, "Notepad++")

        sample = os.path.join(sample_dir, "notepad++.exe")
        output = os.path.join(sample_dir, "notepad++_imports.exe")

        zip_ref = zipfile.ZipFile(sample_file, 'r')
        zip_ref.extractall(self.tmp_dir)
        zip_ref.close()

        notepadpp = lief.parse(sample)

        # Disable ASLR
        notepadpp.optional_header.dll_characteristics &= ~lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE

        # Disable NX protection
        notepadpp.optional_header.dll_characteristics &= ~lief.PE.DLL_CHARACTERISTICS.NX_COMPAT

        builder = lief.PE.Builder(notepadpp)
        builder.build_imports(True).patch_imports(True)
        builder.build()

        builder.write(output)

        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        if sys.platform.startswith("win"):
            subprocess_flags = 0x8000000 # win32con.CREATE_NO_WINDOW?
            p = Popen(["START", output], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=subprocess_flags)
            time.sleep(3)
            q = Popen(["taskkill", "/im", "notepad++_imports.exe"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

            stdout, _ = p.communicate()
            self.logger.debug(stdout.decode("utf8"))

            stdout, _ = q.communicate()
            self.logger.debug(stdout.decode("utf8"))

            self.assertEqual(q.returncode, 0)

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
