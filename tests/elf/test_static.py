#!/usr/bin/env python
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from subprocess import Popen
from unittest import TestCase

import lief
from utils import get_compiler

lief.logging.set_level(lief.logging.LOGGING_LEVEL.INFO)

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

ADD_C = """\
int add(int a, int b) {
    return a + b;
}
"""

class LibAddSample(object):
    COUNT = 0
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.tmp_dir = tempfile.mkdtemp(suffix='_lief_sample_{:d}'.format(LibAddSample.COUNT))
        self.logger.debug("temp dir: {}".format(self.tmp_dir))

        LibAddSample.COUNT += 1

        self.binadd_path = os.path.join(self.tmp_dir, "binadd.c")
        self.add_c_path = os.path.join(self.tmp_dir, "add.c")
        self.binadd_obj = os.path.join(self.tmp_dir, "binadd.o")
        self.binadd_bin = os.path.join(self.tmp_dir, "binadd.exe")

        self.compiler = get_compiler()
        self.logger.debug("Compiler: {}".format(self.compiler))

        with open(self.binadd_path, 'w') as f:
            f.write(BINADD_C)

        with open(self.add_c_path, 'w') as f:
            f.write(ADD_C)

        self._compile_objadd()


    def _compile_objadd(self):
        if os.path.isfile(self.binadd_obj):
            os.remove(self.binadd_obj)

        cmd = [self.compiler, '-c', '-o', self.binadd_obj, self.binadd_path]
        self.logger.debug("Compile 'binadd' with: {}".format(" ".join(cmd)))
        p = Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, _ = p.communicate()
        self.logger.debug(stdout)

    def compile_object_to_bin(self):
        if os.path.isfile(self.binadd_bin):
            os.remove(self.binadd_bin)

        cmd = [self.compiler, '-o', self.binadd_bin, self.binadd_obj, self.add_c_path]
        self.logger.debug("Compile 'binadd' with: {}".format(" ".join(cmd)))
        p = Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, _ = p.communicate()
        self.logger.debug(stdout)

    @property
    def binadd(self):
        return self.binadd_bin

    @property
    def objadd(self):
        return self.binadd_obj

    @property
    def directory(self):
        return self.tmp_dir

    def remove(self):
        if os.path.isdir(self.directory):
            shutil.rmtree(self.directory)

    def __del__(self):
        self.remove()


class TestStatic(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)


    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux")
    def test_write_object(self):
        sample = LibAddSample()
        tmp_file = os.path.join(sample.directory, "newfile.o")
        binadd = lief.parse(sample.objadd)
        init_obj = [str(o).strip() for o in binadd.object_relocations]

        binadd.write(tmp_file)
        binadd = lief.parse(tmp_file)
        new_obj = [str(o).strip() for o in binadd.object_relocations]

        self.assertEqual(len(init_obj), len(new_obj))

        for new, old in zip(new_obj, init_obj):
            self.assertEqual(new, old)

        # Check it can still be compiled
        sample.compile_object_to_bin()
        self.assertEqual(subprocess.check_output([sample.binadd_bin, "2", "3"]).decode('ascii', 'ignore'),
                         'From myLIb, a + b = 5\n')

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux")
    def test_update_addend_object(self):
        sample = LibAddSample()
        tmp_file = os.path.join(sample.directory, "newfile.o")
        binadd = lief.parse(sample.objadd)
        reloc = next(o for o in binadd.object_relocations if o.symbol.name == "add")

        reloc.addend = 0xABCD
        binadd.write(tmp_file)
        binadd = lief.parse(tmp_file)
        reloc = next(o for o in binadd.object_relocations if o.symbol.name == "add")

        self.assertEqual(reloc.addend, 0xABCD)


if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)
