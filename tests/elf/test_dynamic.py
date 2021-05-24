#!/usr/bin/env python
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from subprocess import Popen
from unittest import TestCase

import lief
from utils import get_compiler, get_sample

lief.logging.set_level(lief.logging.LOGGING_LEVEL.WARNING)

CURRENT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
STUB = lief.parse(os.path.join(CURRENT_DIRECTORY, "hello_lief.bin"))

LIBADD_C = """\
#include <stdlib.h>
#include <stdio.h>

int add(int a, int b);

int add(int a, int b) {
  printf("%d + %d = %d\\n", a, b, a + b);
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
class LibAddSample(object):
    COUNT = 0
    def __init__(self, compile_libadd_extra_flags=[], compile_binadd_extra_flags=[]):
        self.logger = logging.getLogger(__name__)
        self.tmp_dir = tempfile.mkdtemp(suffix='_lief_sample_{:d}'.format(LibAddSample.COUNT))
        self.logger.debug("temp dir: {}".format(self.tmp_dir))

        LibAddSample.COUNT += 1

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

        self._compile_libadd(compile_libadd_extra_flags)
        self._compile_binadd(compile_binadd_extra_flags)


    def _compile_libadd(self, extra_flags=[]):
        if os.path.isfile(self.libadd_so):
            os.remove(self.libadd_so)

        CC_FLAGS = ['-fPIC', '-shared', '-Wl,-soname,libadd.so'] + extra_flags
        cmd = [self.compiler, '-o', self.libadd_so] + CC_FLAGS + [self.libadd_path]
        self.logger.debug("Compile 'libadd' with: {}".format(" ".join(cmd)))

        p = Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        stdout, _ = p.communicate()

        self.logger.debug(stdout)


    def _compile_binadd(self, extra_flags=[]):
        if os.path.isfile(self.binadd_bin):
            os.remove(self.binadd_bin)

        # TODO(romain): without the -fPIC -pie it fails on manylinux2014-x86-64
        # but it should be fixed with the new ELF builder
        CC_FLAGS = ['-fPIC', '-pie', '-L', self.tmp_dir] + extra_flags
        cmd = [self.compiler, '-o', self.binadd_bin] + CC_FLAGS + [self.binadd_path, '-ladd']
        self.logger.debug("Compile 'binadd' with: {}".format(" ".join(cmd)))
        p = Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, _ = p.communicate()
        self.logger.debug(stdout)

    @property
    def libadd(self):
        return self.libadd_so

    @property
    def binadd(self):
        return self.binadd_bin

    @property
    def directory(self):
        return self.tmp_dir

    def remove(self):
        if os.path.isdir(self.directory):
            shutil.rmtree(self.directory)


class TestDynamic(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux")
    def test_add_dynamic_symbols(self):
        self._test_add_dynamic_symbols("sysv", False)
        self._test_add_dynamic_symbols("both", True)
        self._test_add_dynamic_symbols("gnu", True)

    def _test_add_dynamic_symbols(self, hash_style, symbol_sorted):
        linkage_option = "-Wl,--hash-style={}".format(hash_style)
        sample = LibAddSample([linkage_option], [linkage_option])
        libadd = lief.parse(sample.libadd)
        binadd = lief.parse(sample.binadd)
        dynamic_symbols = list(libadd.dynamic_symbols)
        for sym in dynamic_symbols:
            libadd.add_dynamic_symbol(sym)
        dynamic_section = libadd.get_section(".dynsym")
        libadd.extend(dynamic_section, dynamic_section.entry_size * len(dynamic_symbols))
        if hash_style != "gnu":
            hash_section = libadd.get_section(".hash")
            libadd.extend(hash_section, hash_section.entry_size * len(dynamic_symbols))
        libadd.write(sample.libadd)

        p = Popen([sample.binadd_bin, '1', '2'],
                  stdout=subprocess.PIPE,
                  stderr=subprocess.STDOUT,
                  env={"LD_LIBRARY_PATH": sample.directory})
        stdout, _ = p.communicate()
        if p.returncode > 0:
            self.logger.fatal(stdout.decode("utf8"))
            self.assertEqual(p.returncode, 0)
        self.logger.debug(stdout.decode("utf8"))
        self.assertIsNotNone(re.search(r'From myLIb, a \+ b = 3', stdout.decode("utf8")))

        libadd = lief.parse(sample.libadd)
        dynamic_section = libadd.get_section(".dynsym")
        # TODO: Size of libadd.dynamic_symbols is larger than  dynamic_symbols_size.
        dynamic_symbols_size = int(dynamic_section.size / dynamic_section.entry_size)
        dynamic_symbols = list(libadd.dynamic_symbols)[:dynamic_symbols_size]
        if symbol_sorted:
            first_not_null_symbol_index = dynamic_section.information
            first_exported_symbol_index = next(
                i for i, sym in enumerate(dynamic_symbols) if sym.shndx != 0)
            self.assertTrue(all(map(
                lambda sym: sym.shndx == 0 and sym.binding == lief.ELF.SYMBOL_BINDINGS.LOCAL,
                        dynamic_symbols[:first_not_null_symbol_index])))
            self.assertTrue(all(map(
                lambda sym: sym.shndx == 0 and sym.binding != lief.ELF.SYMBOL_BINDINGS.LOCAL,
                dynamic_symbols[first_not_null_symbol_index:first_exported_symbol_index])))
            self.assertTrue(all(map(
                lambda sym: sym.shndx != 0,
                dynamic_symbols[first_exported_symbol_index:])))

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux")
    def test_remove_library(self):
        sample = LibAddSample()
        libadd = lief.parse(sample.libadd)
        binadd = lief.parse(sample.binadd)

        libadd_needed = binadd.get_library("libadd.so")
        binadd -= libadd_needed
        self.assertFalse(binadd.has_library("libadd.so"))


    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux")
    def test_remove_tag(self):
        sample = LibAddSample()
        libadd = lief.parse(sample.libadd)
        binadd = lief.parse(sample.binadd)
        self.logger.debug("BEFORE")
        list(map(lambda e : self.logger.debug(e), binadd.dynamic_entries))
        self.logger.debug("")
        binadd -= lief.ELF.DYNAMIC_TAGS.NEEDED

        self.logger.debug("AFTER")
        list(map(lambda e : self.logger.debug(e), binadd.dynamic_entries))
        self.logger.debug("")

        self.assertTrue(all(e.tag != lief.ELF.DYNAMIC_TAGS.NEEDED for e in binadd.dynamic_entries))

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux")
    def test_runpath_api(self):
        sample = LibAddSample()
        libadd = lief.parse(sample.libadd)
        binadd = lief.parse(sample.binadd)

        rpath = lief.ELF.DynamicEntryRunPath()
        rpath = binadd.add(rpath)
        self.logger.debug(rpath)
        rpath += "/tmp"

        self.logger.debug(rpath)

        self.assertEqual(rpath.paths, ["/tmp"])
        self.assertEqual(rpath.runpath, "/tmp")

        rpath.insert(0, "/foo")

        self.assertEqual(rpath.paths, ["/foo", "/tmp"])
        self.assertEqual(rpath.runpath, "/foo:/tmp")

        rpath.paths = ["/foo", "/tmp", "/bar"]

        self.logger.debug(rpath)

        self.assertEqual(rpath.paths, ["/foo", "/tmp", "/bar"])
        self.assertEqual(rpath.runpath, "/foo:/tmp:/bar")

        rpath -= "/tmp"

        self.logger.debug(rpath)

        self.assertEqual(rpath.runpath, "/foo:/bar")

        rpath.remove("/foo").remove("/bar")

        self.logger.debug(rpath)

        self.assertEqual(rpath.runpath, "")

        self.logger.debug(rpath)



    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux")
    def test_change_libname(self):
        sample = LibAddSample()
        libadd = lief.parse(sample.libadd)
        binadd = lief.parse(sample.binadd)

        new_name = "libwhichhasalongverylongname.so"


        self.assertIn(lief.ELF.DYNAMIC_TAGS.SONAME, libadd)

        so_name = libadd[lief.ELF.DYNAMIC_TAGS.SONAME]
        self.logger.debug("DT_SONAME: {}".format(so_name.name))
        so_name.name = new_name

        libfoo_path = os.path.join(sample.directory, new_name)
        self.logger.debug(libfoo_path)
        libadd.write(libfoo_path)

        libfoo = lief.parse(libfoo_path)

        new_so_name = libadd[lief.ELF.DYNAMIC_TAGS.SONAME]
        # Check builder did the job right
        self.assertEqual(new_so_name.name, new_name)

        libadd_needed = binadd.get_library("libadd.so")
        libadd_needed.name = new_name

        # Add a RPATH entry
        rpath = lief.ELF.DynamicEntryRunPath(sample.directory)
        rpath = binadd.add(rpath)
        self.logger.debug(rpath)

        new_binadd_path = os.path.join(sample.directory, "binadd_updated.bin")
        self.logger.debug(new_binadd_path)
        binadd.write(new_binadd_path)

        # Remove original binaries:
        os.remove(sample.libadd)
        os.remove(sample.binadd)

        # Run the new executable
        st = os.stat(libfoo_path)
        os.chmod(libfoo_path, st.st_mode | stat.S_IEXEC)

        st = os.stat(new_binadd_path)
        os.chmod(new_binadd_path, st.st_mode | stat.S_IEXEC)

        p = Popen([new_binadd_path, '1', '2'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT)
                #env={"LD_LIBRARY_PATH": sample.directory}) # Shouldn't be needed if RPATH inject succeed
        stdout, _ = p.communicate()
        if p.returncode > 0:
            self.logger.fatal(stdout.decode("utf8"))
            self.assertEqual(p.returncode, 0)

        self.logger.debug(stdout.decode("utf8"))
        self.assertIsNotNone(re.search(r'From myLIb, a \+ b = 3', stdout.decode("utf8")))

        sample.remove()



if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)
