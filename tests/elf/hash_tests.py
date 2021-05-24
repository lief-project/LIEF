#!/usr/bin/env python3
import unittest
import logging
import os
import stat
import sys
import re
import subprocess
import platform
import tempfile
import shutil

from subprocess import Popen

import lief

from unittest import TestCase
from utils import get_sample, get_compiler

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

class TestHash(TestCase):

    def setUp(self):
        self.logger  = logging.getLogger(__name__)
        self.tmp_dir = tempfile.mkdtemp(suffix='_lief_testhash')
        self.logger.debug("temp dir: {}".format(self.tmp_dir))

        self.binadd_path = os.path.join(self.tmp_dir, "binadd.c")
        self.libadd_path = os.path.join(self.tmp_dir, "libadd.c")

        self.libadd_so  = os.path.join(self.tmp_dir, "libadd.so")
        self.binadd_bin = os.path.join(self.tmp_dir, "binadd.bin")

        self.compiler = get_compiler()
        if self.compiler is None:
            self.logger.error("Unable to find a compiler")
            sys.exit(0)

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

    def obfuscate(self):

        libadd = lief.parse(self.libadd_so)
        binadd = lief.parse(self.binadd_bin)

        libadd_dynsym = libadd.dynamic_symbols
        binadd_dynsym = binadd.dynamic_symbols

        # Change add in the libary
        for sym in libadd_dynsym:
            if sym.name == "add":
                sym.name = "abc"

        # Change "add" in the binary
        for sym in binadd_dynsym:
            if sym.name == "add":
                sym.name = "abc"


        # change library name in the binary
        for entry in binadd.dynamic_entries:
            if entry.tag == lief.ELF.DYNAMIC_TAGS.NEEDED and entry.name == "libadd.so":
                entry.name = "libabc.so"

        libadd_modified = os.path.join(self.tmp_dir, "libabc.so")
        binadd_modified = os.path.join(self.tmp_dir, "binadd_obf.bin")

        libadd.write(libadd_modified);
        binadd.write(binadd_modified)

        st = os.stat(libadd_modified)
        os.chmod(libadd_modified, st.st_mode | stat.S_IEXEC)

        st = os.stat(binadd_modified)
        os.chmod(binadd_modified, st.st_mode | stat.S_IEXEC)

        p = Popen([binadd_modified, '1', '2'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env={"LD_LIBRARY_PATH": self.tmp_dir})
        stdout, _ = p.communicate()

        self.assertIn('From myLIb, a + b = 3', stdout.decode("utf8"))


    @unittest.skipUnless(sys.platform.startswith("linux") and sys.version_info >= (3, 5), "requires Linux")
    def test_gnuhash(self):
        self.compile_libadd(self.libadd_path, ['-Wl,--hash-style=gnu'])
        self.compile_binadd(self.binadd_path, ['-Wl,--hash-style=gnu'])
        self.obfuscate()


    @unittest.skipUnless(sys.platform.startswith("linux") and sys.version_info >= (3, 5), "requires Linux")
    def test_sysv(self):
        self.compile_libadd(self.libadd_path, ['-Wl,--hash-style=sysv'])
        self.compile_binadd(self.binadd_path, ['-Wl,--hash-style=sysv'])
        self.obfuscate()



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

