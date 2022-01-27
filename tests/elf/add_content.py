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
from utils import get_sample, get_compiler, is_aarch64, is_x86_64, is_linux

CURRENT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
STUB_FILE = None
if is_x86_64():
    STUB_FILE = "hello_lief.bin"
elif is_aarch64():
    STUB_FILE = "hello_lief_aarch64.bin"

STUB = lief.parse(os.path.join(CURRENT_DIRECTORY, STUB_FILE))


LIBADD_C = """\
#include <stdlib.h>
#include <stdio.h>

int add(int a, int b);

int add(int a, int b) {
  printf("%d + %d = %d\\n", a, b, a+b);
  return a + b;
}
"""

BINADD_C = """\
#include <stdio.h>
#include <stdlib.h>

int add(int a, int b);

int main(int argc, char **argv) {
  if (argc != 3) {
    printf("Usage: %s <a> <b>\\n", argv[0]);
    exit(-1);
  }

  int res = add(atoi(argv[1]), atoi(argv[2]));
  printf("From myLIb, a + b = %d\\n", res);
  return 0;
}
"""


class TestAddContent(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.tmp_dir = tempfile.mkdtemp(suffix='_lief_test_content')
        self.logger.debug("temp dir: {}".format(self.tmp_dir))

        self.binadd_path = os.path.join(self.tmp_dir, "binadd.c")
        self.libadd_path = os.path.join(self.tmp_dir, "libadd.c")

        self.libadd_so  = os.path.join(self.tmp_dir, "libadd.so")
        self.binadd_bin = os.path.join(self.tmp_dir, "binadd.bin")

        self.compiler = get_compiler()

        self.logger.debug("Compiler: {}".format(self.compiler))

        with open(self.binadd_path, 'w') as f:
            f.write(BINADD_C)

        with open(self.libadd_path, 'w') as f:
            f.write(LIBADD_C)

    def compile_libadd(self, input, extra_flags=[]):
        if os.path.isfile(self.libadd_so):
            os.remove(self.libadd_so)
        CC_FLAGS = ['-fPIC', '-shared'] + extra_flags
        cmd = [self.compiler, '-o', self.libadd_so] + CC_FLAGS + [input]
        self.logger.debug("Compile 'libadd' with: {}".format(" ".join(cmd)))
        p = Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, _ = p.communicate()
        self.logger.debug(stdout)


    def compile_binadd(self, input, extra_flags=[]):
        if os.path.isfile(self.binadd_bin):
            os.remove(self.binadd_bin)

        CC_FLAGS = ['-L', self.tmp_dir] + extra_flags
        cmd = [self.compiler, '-o', self.binadd_bin] + CC_FLAGS + [input, '-ladd']
        self.logger.debug("Compile 'binadd' with: {}".format(" ".join(cmd)))
        p = Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, _ = p.communicate()
        self.logger.debug(stdout)


    @unittest.skipUnless(is_linux(), "requires Linux")
    def test_simple(self):
        self.compile_libadd(self.libadd_path)
        self.compile_binadd(self.binadd_path)

        libadd = lief.parse(self.libadd_so)
        for i in range(10):
            segment = libadd.add(STUB.segments[0])
            segment.alignment = 0x1000

            new_ep = (STUB.header.entrypoint - STUB.segments[0].virtual_address) + segment.virtual_address

            if libadd.has(lief.ELF.DYNAMIC_TAGS.INIT_ARRAY):
                init_array = libadd.get(lief.ELF.DYNAMIC_TAGS.INIT_ARRAY)
                callbacks = init_array.array
                callbacks[0] = new_ep
                init_array.array = callbacks

            if libadd.has(lief.ELF.DYNAMIC_TAGS.INIT):
                init = libadd.get(lief.ELF.DYNAMIC_TAGS.INIT)
                init.value = new_ep

        libadd.write(self.libadd_so)

        st = os.stat(self.libadd_so)
        os.chmod(self.libadd_so, st.st_mode | stat.S_IEXEC)

        p = Popen([self.binadd_bin, '1', '2'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env={"LD_LIBRARY_PATH": self.tmp_dir})
        stdout, _ = p.communicate()
        self.logger.debug(stdout.decode("utf8"))

        self.assertIsNotNone(re.search(r'LIEF is Working', stdout.decode("utf8")))

    def tearDown(self):
        # Delete it
        return
        if os.path.isdir(self.tmp_dir):
            shutil.rmtree(self.tmp_dir)

if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)

