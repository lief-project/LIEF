import logging
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from collections import namedtuple

import lief
from utils import get_compiler, is_linux, is_x86_64, is_aarch64

lief.logging.set_level(lief.logging.LOGGING_LEVEL.INFO)

class CommandResult(object):
    def __init__(self, output, error, retcode, process=None):
        self.output = output
        self.error = error
        self.retcode = retcode
        self.process = process

    def __bool__(self):
        return not self.retcode

    def __str__(self):
        if bool(self):
            return self.output
        return self.error




LIBADD = """\
#include <stdlib.h>
#include <stdio.h>
#define LOCAL __attribute__ ((visibility ("hidden")))

LOCAL int add_hidden(int a, int b) {
  printf("[LOCAL] %d + %d = %d\\n", a, b, a+b);
  return a + b;
}


int main(int argc, char** argv) {

  if (argc != 3) {
    printf("Usage: %s <a> <b>\\n", argv[0]);
    exit(-1);
  }

  printf("Hello\\n");
  int res = add_hidden(atoi(argv[1]), atoi(argv[2]));
  printf("From add_hidden@libadd.so a + b = %d\\n", res);
  return 0;
}
"""


BINADD = """\
#include <stdio.h>
#include <stdlib.h>
extern int add_hidden(int a, int b);

int main(int argc, char **argv) {
  if (argc != 3) {
    printf("Usage: %s <a> <b>\\n", argv[0]);
    exit(-1);
  }

  printf("Hello\\n");
  int res = add_hidden(atoi(argv[1]), atoi(argv[2]));
  printf("From add_hidden@libadd.so a + b = %d\\n", res);
  return 0;
}
"""


class TestBin2Lib(unittest.TestCase):
    LOGGER = logging.getLogger(__name__)

    def setUp(self):
        self._logger = logging.getLogger(__name__)

    @staticmethod
    def run_cmd(cmd):
        TestBin2Lib.LOGGER.debug("Running: '{}'".format(cmd))
        cmd = shlex.split(cmd)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = p.communicate()

        if stdout:
            TestBin2Lib.LOGGER.debug(stdout)

        if stderr:
            TestBin2Lib.LOGGER.error(stderr)

        return CommandResult(stdout, stderr, p.returncode)

    @unittest.skipUnless(is_linux(), "requires Linux")
    def test_libadd(self):


        _, binaddc = tempfile.mkstemp(prefix="binadd_", suffix=".c")
        _, libaddc = tempfile.mkstemp(prefix="libadd_", suffix=".c")

        self._logger.debug(binaddc)
        self._logger.debug(libaddc)

        fd, binadd  = tempfile.mkstemp(prefix="binadd_", suffix=".bin")
        _, libadd  = tempfile.mkstemp(prefix="libadd_", suffix=".so")
        _, libadd2 = tempfile.mkstemp(prefix="libadd2_", suffix=".so")

        self._logger.debug(binadd)
        self._logger.debug(libadd)
        self._logger.debug(libadd2)


        with open(binaddc, 'w') as f:
            f.write(BINADD)

        with open(libaddc, 'w') as f:
            f.write(LIBADD)

        compiler = get_compiler()

        fmt = ""
        if is_x86_64():
            fmt = "{compiler} -Wl,--export-dynamic -mcmodel=large -fPIE -pie -o {output} {input}"

        if is_aarch64():
            fmt = "{compiler} -Wl,--export-dynamic -fPIE -pie -o {output} {input}"

        # Compile libadd
        r = self.run_cmd(fmt.format(
            compiler=compiler,
            output=libadd,
            input=libaddc))
        self.assertTrue(r, msg="Unable to compile libadd")

        libadd = lief.parse(libadd)

        libadd_hidden            = libadd.get_symbol("add_hidden")
        libadd_hidden.binding    = lief.ELF.SYMBOL_BINDINGS.GLOBAL
        libadd_hidden.visibility = lief.ELF.SYMBOL_VISIBILITY.DEFAULT
        libadd_hidden            = libadd.add_dynamic_symbol(libadd_hidden, lief.ELF.SymbolVersion.global_)
        if lief.ELF.DYNAMIC_TAGS.FLAGS_1 in libadd and libadd[lief.ELF.DYNAMIC_TAGS.FLAGS_1].has(lief.ELF.DYNAMIC_FLAGS_1.PIE):
            libadd[lief.ELF.DYNAMIC_TAGS.FLAGS_1].remove(lief.ELF.DYNAMIC_FLAGS_1.PIE)

        self._logger.debug(libadd_hidden)

        libadd.add(lief.ELF.DynamicSharedObject(os.path.basename(libadd2)))

        libadd.write(libadd2)

        lib_directory = os.path.dirname(libadd2)
        libname = os.path.basename(libadd2)[3:-3] # libadd.so ---> add

        fmt = ""
        if is_x86_64():
            fmt = "{compiler} -Wl,--export-dynamic -mcmodel=large -fPIE -pie -Wl,-rpath={libdir} -L{libdir} -o {output} {input} -l{libadd2}"

        if is_aarch64():
            fmt = "{compiler} -Wl,--export-dynamic -fPIE -pie -Wl,-rpath={libdir} -L{libdir} -o {output} {input} -l{libadd2}"

        r = self.run_cmd(fmt.format(
            compiler=compiler,
            libdir=lib_directory,
            libadd2=libname,
            output=binadd,
            input=binaddc))
        self.assertTrue(r, msg="Unable to compile binadd")

        os.close(fd)
        st = os.stat(binadd)
        os.chmod(binadd, st.st_mode | stat.S_IEXEC)

        r = self.run_cmd(binadd + " 1 2")
        self.assertTrue(r)
        self.assertIn("From add_hidden@libadd.so a + b = 3", r.output)


    @unittest.skipUnless(is_linux() and is_x86_64(), "requires Linux")
    def test_libadd_api(self):
        _, binaddc = tempfile.mkstemp(prefix="binadd_", suffix=".c")
        _, libaddc = tempfile.mkstemp(prefix="libadd_", suffix=".c")

        self._logger.debug(binaddc)
        self._logger.debug(libaddc)

        fd, binadd  = tempfile.mkstemp(prefix="binadd_", suffix=".bin")
        _, libadd  = tempfile.mkstemp(prefix="libadd_", suffix=".so")
        _, libadd2 = tempfile.mkstemp(prefix="libadd2_", suffix=".so")

        self._logger.debug(binadd)
        self._logger.debug(libadd)
        self._logger.debug(libadd2)


        with open(binaddc, 'w') as f:
            f.write(BINADD)

        with open(libaddc, 'w') as f:
            f.write(LIBADD)

        compiler = get_compiler()

        # Compile libadd
        fmt = ""
        if is_x86_64():
            fmt = "{compiler} -Wl,--export-dynamic -mcmodel=large -fPIE -pie -o {output} {input}"

        if is_aarch64():
            fmt = "{compiler} -Wl,--export-dynamic -fPIE -pie -o {output} {input}"

        r = self.run_cmd(fmt.format(
            compiler=compiler,
            output=libadd,
            input=libaddc))
        self.assertTrue(r, msg="Unable to compile libadd")

        libadd = lief.parse(libadd)
        libadd.export_symbol("add_hidden")

        if lief.ELF.DYNAMIC_TAGS.FLAGS_1 in libadd and libadd[lief.ELF.DYNAMIC_TAGS.FLAGS_1].has(lief.ELF.DYNAMIC_FLAGS_1.PIE):
            libadd[lief.ELF.DYNAMIC_TAGS.FLAGS_1].remove(lief.ELF.DYNAMIC_FLAGS_1.PIE)

        libadd.write(libadd2)

        lib_directory = os.path.dirname(libadd2)
        libname = os.path.basename(libadd2)[3:-3] # libadd.so ---> add

        fmt = ""
        if is_x86_64():
            fmt = "{compiler} -Wl,--export-dynamic -mcmodel=large -fPIE -pie -Wl,-rpath={libdir} -L{libdir} -o {output} {input} -l{libadd2}"

        if is_aarch64():
            fmt = "{compiler} -Wl,--export-dynamic -fPIE -pie -Wl,-rpath={libdir} -L{libdir} -o {output} {input} -l{libadd2}"

        r = self.run_cmd(fmt.format(
            compiler=compiler,
            libdir=lib_directory,
            libadd2=libname,
            output=binadd,
            input=binaddc))
        self.assertTrue(r, msg="Unable to compile binadd")

        os.close(fd)
        st = os.stat(binadd)
        os.chmod(binadd, st.st_mode | stat.S_IEXEC)

        r = self.run_cmd(binadd + " 1 2")
        self.assertTrue(r)
        self.assertIn("From add_hidden@libadd.so a + b = 3", r.output)


    @unittest.skipUnless(is_linux() and is_x86_64(), "requires Linux")
    def test_libadd_api2(self):
        _, binaddc = tempfile.mkstemp(prefix="binadd_", suffix=".c")
        _, libaddc = tempfile.mkstemp(prefix="libadd_", suffix=".c")

        self._logger.debug(binaddc)
        self._logger.debug(libaddc)

        fd, binadd  = tempfile.mkstemp(prefix="binadd_", suffix=".bin")
        _, libadd  = tempfile.mkstemp(prefix="libadd_", suffix=".so")
        _, libadd2 = tempfile.mkstemp(prefix="libadd2_", suffix=".so")

        self._logger.debug(binadd)
        self._logger.debug(libadd)
        self._logger.debug(libadd2)


        with open(binaddc, 'w') as f:
            f.write(BINADD)

        with open(libaddc, 'w') as f:
            f.write(LIBADD)

        compiler = get_compiler()

        fmt = ""
        if is_x86_64():
            fmt = "{compiler} -Wl,--export-dynamic -mcmodel=large -fPIE -pie -o {output} {input}"

        if is_aarch64():
            fmt = "{compiler} -Wl,--export-dynamic -fPIE -pie -o {output} {input}"


        # Compile libadd
        r = self.run_cmd(fmt.format(
            compiler=compiler,
            output=libadd,
            input=libaddc))
        self.assertTrue(r, msg="Unable to compile libadd")

        libadd = lief.parse(libadd)
        add_hidden_static = libadd.get_static_symbol("add_hidden")
        libadd.add_exported_function(add_hidden_static.value, add_hidden_static.name)

        if lief.ELF.DYNAMIC_TAGS.FLAGS_1 in libadd and libadd[lief.ELF.DYNAMIC_TAGS.FLAGS_1].has(lief.ELF.DYNAMIC_FLAGS_1.PIE):
            libadd[lief.ELF.DYNAMIC_TAGS.FLAGS_1].remove(lief.ELF.DYNAMIC_FLAGS_1.PIE)
        libadd.write(libadd2)

        lib_directory = os.path.dirname(libadd2)
        libname = os.path.basename(libadd2)[3:-3] # libadd.so ---> add

        r = self.run_cmd("{compiler} -Wl,--export-dynamic -mcmodel=large -fPIE -pie -Wl,-rpath={libdir} -L{libdir} -o {output} {input} -l{libadd2}".format(
            compiler=compiler,
            libdir=lib_directory,
            libadd2=libname,
            output=binadd,
            input=binaddc))
        self.assertTrue(r, msg="Unable to compile binadd")

        os.close(fd)
        st = os.stat(binadd)
        os.chmod(binadd, st.st_mode | stat.S_IEXEC)

        r = self.run_cmd(binadd + " 1 2")
        self.assertTrue(r)
        self.assertIn("From add_hidden@libadd.so a + b = 3", r.output)


if __name__ == "__main__":

    root_logger = logging.getLogger()
    root_logger.addHandler(logging.StreamHandler())

    unittest.main(verbosity=2)
