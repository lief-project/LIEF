#!/usr/bin/env python3
import os
import stat
import re
import pytest
import subprocess
from pathlib import Path

from subprocess import Popen

import lief

from utils import get_compiler, is_linux

if not is_linux():
    pytest.skip("requires Linux", allow_module_level=True)

COMPILER = get_compiler()

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


def compile_libadd(tmp_path: Path, flag: str):
    outfile = "libadd.so"
    CC_FLAGS = ['-fPIC', '-shared'] + [flag]
    cmd = [COMPILER, '-o', outfile] + CC_FLAGS + ["libadd.c"]
    print("Compile 'libadd' with: {}".format(" ".join(cmd)))
    with Popen(cmd, cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as P:
        stdout = P.stdout.read()
        print(stdout)
        return tmp_path / outfile


def compile_binadd(tmp_path: Path, flag: str):
    outfile = "binadd.bin"
    CC_FLAGS = ['-L', tmp_path.as_posix()] + [flag]
    cmd = [COMPILER, '-o', outfile] + CC_FLAGS + ["binadd.c", '-ladd']
    print("Compile 'binadd' with: {}".format(" ".join(cmd)))
    with Popen(cmd, cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as P:
        stdout = P.stdout.read()
        print(stdout)
        return tmp_path / outfile



@pytest.mark.parametrize("flag", [
    '-Wl,--hash-style=gnu', '-Wl,--hash-style=sysv'
])
def test_simple(tmp_path: Path, flag: str):
    if not is_linux():
        pytest.skip("unsupported system")

    (tmp_path / "libadd.c").write_text(LIBADD_C)
    (tmp_path / "binadd.c").write_text(BINADD_C)

    libadd_so  = tmp_path / "libadd.so"
    binadd_bin = tmp_path / "binadd.bin"

    libadd_so  = compile_libadd(tmp_path, flag)
    binadd_bin = compile_binadd(tmp_path, flag)

    libadd = lief.ELF.parse(libadd_so.as_posix())
    binadd = lief.ELF.parse(binadd_bin.as_posix())

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
        if (entry.tag == lief.ELF.DynamicEntry.TAG.NEEDED and
            isinstance(entry, lief.ELF.DynamicEntryLibrary) and
            entry.name == "libadd.so"
        ):
            entry.name = "libabc.so"

    libadd_modified = tmp_path / "libabc.so"
    binadd_modified = tmp_path / "binadd_obf.bin"

    libadd.write(libadd_modified.as_posix())
    binadd.write(binadd_modified.as_posix())

    st = os.stat(libadd_modified)
    os.chmod(libadd_modified, st.st_mode | stat.S_IEXEC)

    st = os.stat(binadd_modified)
    os.chmod(binadd_modified, st.st_mode | stat.S_IEXEC)

    popen_args = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "env":    {"LD_LIBRARY_PATH": tmp_path.as_posix()},
    }
    with Popen([binadd_bin, '1', '2'], **popen_args) as P: # type: ignore
        stdout = P.stdout.read().decode("utf8")
        print(stdout)
        assert "From myLIb, a + b = 3" in stdout
