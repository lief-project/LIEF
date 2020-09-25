#!/usr/bin/env python
import unittest
import logging
import os
import sys
import stat
import re
import subprocess
import tempfile
import shutil
from subprocess import Popen

import lief
from lief.ELF import Section

from unittest import TestCase
from utils import get_sample, has_recent_glibc

class TestGOTPatch(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.tmp_dir = tempfile.mkdtemp(suffix='_lief_test_466')
        self.logger.debug("temp dir: {}".format(self.tmp_dir))


    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux")
    @unittest.skipUnless(has_recent_glibc(), "Need a recent GLIBC version")
    def test_freebl(self):
        libfreebl3_path = get_sample('ELF/ELF64_x86-64_library_libfreebl3.so')
        output_ls         = os.path.join(self.tmp_dir, "ls.new")
        output_libfreebl3 = os.path.join(self.tmp_dir, "libfreebl3.so")

        libfreebl3 = lief.parse(libfreebl3_path)
        ls         = lief.parse("/usr/bin/ls")

        ls[lief.ELF.DYNAMIC_TAGS.FLAGS_1].remove(lief.ELF.DYNAMIC_FLAGS_1.PIE)

        ls.add_library("libfreebl3.so")

        ls         += lief.ELF.DynamicEntryRunPath("$ORIGIN")
        libfreebl3 += lief.ELF.DynamicEntryRunPath("$ORIGIN")

        ls.write(output_ls)
        libfreebl3.write(output_libfreebl3)

        st = os.stat(output_ls)
        os.chmod(output_ls, st.st_mode | stat.S_IEXEC)

        st = os.stat(output_libfreebl3)
        os.chmod(output_libfreebl3, st.st_mode | stat.S_IEXEC)

        p = Popen([output_ls, "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, _ = p.communicate()
        self.logger.debug(stdout.decode("utf8"))
        self.assertIsNotNone(re.search(r'ls \(GNU coreutils\) ', stdout.decode("utf8")))
        self.assertEqual(p.returncode, 0)

    def tearDown(self):
        # Delete it
        if os.path.isdir(self.tmp_dir):
            shutil.rmtree(self.tmp_dir)

if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)

