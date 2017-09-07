#!/usr/bin/env python
import signal
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
from lief.ELF import Segment
from lief import Logger
#Logger.set_level(lief.LOGGING_LEVEL.DEBUG)

from unittest import TestCase
from utils import get_sample

CURRENT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class TestChangeInterpreter(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.tmp_dir = tempfile.mkdtemp(suffix='_lief_test_add_segment')
        self.logger.debug("temp dir: {}".format(self.tmp_dir))


    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux")
    def test_misc(self):
        list_binaries = [
        '/usr/bin/ls',
        '/usr/bin/ssh',
        '/usr/bin/nm',
        '/usr/bin/cp',
        '/usr/bin/find',
        '/usr/bin/file',
        ]
        for binary in list_binaries:
            self.logger.debug("Test with '{}'".format(binary))
            self.change_interpreter(binary)


    def change_interpreter(self, target):
        if not os.path.isfile(target):
            return

        name = os.path.basename(target)
        target = lief.parse(target)
        new_interpreter = os.path.join(self.tmp_dir, os.path.basename(target.interpreter))
        if not os.path.islink(new_interpreter):
            os.symlink(target.interpreter, new_interpreter)
        target.interpreter = new_interpreter
        output = os.path.join(self.tmp_dir, "{}.interpreter".format(name))
        target.write(output)

        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        p = Popen(output, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, _ = p.communicate()

        self.logger.debug(stdout.decode("utf8"))
        self.assertNotEqual(p.returncode, -signal.SIGSEGV, "{} segfault!!!!".format(name))


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

