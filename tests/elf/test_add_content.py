#!/usr/bin/env python
import os
import stat
import re
import subprocess
import pytest
from pathlib import Path
from subprocess import Popen

import lief

from utils import get_compiler, is_aarch64, is_x86_64, is_linux

if not is_linux():
    pytest.skip("requires Linux", allow_module_level=True)

CURRENT_DIRECTORY = Path(__file__).parent
STUB_FILE = None
if is_x86_64():
    STUB_FILE = "hello_lief.bin"
elif is_aarch64():
    STUB_FILE = "hello_lief_aarch64.bin"

assert STUB_FILE is not None

STUB = lief.ELF.parse((CURRENT_DIRECTORY / STUB_FILE).as_posix())

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


def compile_libadd(tmp_path: Path):
    outfile = "libadd.so"
    CC_FLAGS = ['-fPIC', '-shared']
    cmd = [COMPILER, '-o', outfile] + CC_FLAGS + ["libadd.c"]
    print("Compile 'libadd' with: {}".format(" ".join(cmd)))
    with Popen(cmd, cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as P:
        stdout = P.stdout.read()
        print(stdout)
        return tmp_path / outfile


def compile_binadd(tmp_path: Path):
    outfile = "binadd.bin"
    CC_FLAGS = ['-L', tmp_path.as_posix()]
    cmd = [COMPILER, '-o', outfile] + CC_FLAGS + ["binadd.c", '-ladd']
    print("Compile 'binadd' with: {}".format(" ".join(cmd)))
    with Popen(cmd, cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as P:
        stdout = P.stdout.read()
        print(stdout)
        return tmp_path / outfile


def test_simple(tmp_path: Path):
    if not is_linux():
        pytest.skip("unsupported system")

    (tmp_path / "libadd.c").write_text(LIBADD_C)
    (tmp_path / "binadd.c").write_text(BINADD_C)

    libadd_so  = tmp_path / "libadd.so"
    binadd_bin = tmp_path / "binadd.bin"

    libadd_so  = compile_libadd(tmp_path)
    binadd_bin = compile_binadd(tmp_path)

    libadd = lief.ELF.parse(libadd_so.as_posix())
    for _ in range(10):
        segment = libadd.add(STUB.segments[0])
        segment.alignment = 0x1000

        new_ep = (STUB.header.entrypoint - STUB.segments[0].virtual_address) + segment.virtual_address

        if libadd.has(lief.ELF.DynamicEntry.TAG.INIT_ARRAY):
            init_array = libadd.get(lief.ELF.DynamicEntry.TAG.INIT_ARRAY)
            assert isinstance(init_array, lief.ELF.DynamicEntryArray)
            callbacks = init_array.array
            callbacks[0] = new_ep
            init_array.array = callbacks

        if libadd.has(lief.ELF.DynamicEntry.TAG.INIT):
            init = libadd.get(lief.ELF.DynamicEntry.TAG.INIT)
            init.value = new_ep

    libadd.write(libadd_so.as_posix())

    st = os.stat(libadd_so)
    os.chmod(libadd_so, st.st_mode | stat.S_IEXEC)
    popen_args = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "env":    {"LD_LIBRARY_PATH": tmp_path.as_posix()},
    }

    with Popen([binadd_bin, '1', '2'], **popen_args) as P: # type: ignore
        stdout = P.stdout.read().decode("utf8")
        print(stdout)
        assert re.search(r'LIEF is Working', stdout) is not None
