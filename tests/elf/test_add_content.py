import os
import re
import stat
import subprocess
from functools import lru_cache
from pathlib import Path
from subprocess import Popen
from typing import Any

import lief
import pytest
from utils import check_layout, get_compiler, is_aarch64, is_linux, is_x86_64

if not is_linux():
    pytest.skip("requires Linux", allow_module_level=True)

CWD = Path(__file__).parent

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


@lru_cache(maxsize=1)
def _get_stub() -> lief.ELF.Binary:
    if is_x86_64():
        stub_path = CWD / "hello_lief.bin"
    elif is_aarch64():
        stub_path = CWD / "hello_lief_aarch64.bin"
    else:
        raise RuntimeError("Unsupported platform")

    assert stub_path.is_file()
    stub = lief.ELF.parse(stub_path)
    assert stub is not None
    return stub


def compile_libadd(tmp_path: Path) -> Path:
    outfile = tmp_path / "libadd.so"
    CC_FLAGS = ["-fPIC", "-shared"]
    cmd = [COMPILER, "-o", str(outfile)] + CC_FLAGS + ["libadd.c"]
    lief.logging.info("Compile 'libadd' with: {}".format(" ".join(cmd)))
    with Popen(
        cmd, cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    ) as P:
        assert P.stdout is not None
        stdout = P.stdout.read()
        lief.logging.info(stdout)
        return outfile


def compile_binadd(tmp_path: Path):
    outfile = tmp_path / "binadd.bin"
    CC_FLAGS = ["-L", tmp_path.as_posix()]
    cmd = [COMPILER, "-o", str(outfile)] + CC_FLAGS + ["binadd.c", "-ladd"]
    lief.logging.info("Compile 'binadd' with: {}".format(" ".join(cmd)))
    with Popen(
        cmd, cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    ) as P:
        assert P.stdout is not None
        stdout = P.stdout.read()
        lief.logging.info(stdout)
        return outfile


def test_simple(tmp_path: Path):
    (tmp_path / "libadd.c").write_text(LIBADD_C)
    (tmp_path / "binadd.c").write_text(BINADD_C)

    libadd_so = compile_libadd(tmp_path)
    binadd_bin = compile_binadd(tmp_path)

    libadd = lief.ELF.parse(libadd_so)
    assert libadd is not None
    stub = _get_stub()
    for _ in range(10):
        segment = libadd.add(stub.segments[0])
        assert segment is not None
        segment.alignment = 0x1000

        new_ep = (
            stub.header.entrypoint - stub.segments[0].virtual_address
        ) + segment.virtual_address

        if libadd.has(lief.ELF.DynamicEntry.TAG.INIT_ARRAY):
            init_array = libadd.get(lief.ELF.DynamicEntry.TAG.INIT_ARRAY)
            assert isinstance(init_array, lief.ELF.DynamicEntryArray)
            callbacks = init_array.array
            callbacks[0] = new_ep
            init_array.array = callbacks

        if libadd.has(lief.ELF.DynamicEntry.TAG.INIT):
            init = libadd.get(lief.ELF.DynamicEntry.TAG.INIT)
            assert init is not None
            init.value = new_ep

    libadd.write(libadd_so)

    check_layout(libadd_so)

    st = os.stat(libadd_so)
    os.chmod(libadd_so, st.st_mode | stat.S_IEXEC)
    popen_args: dict[str, Any] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "universal_newlines": True,
        "env": {"LD_LIBRARY_PATH": tmp_path.as_posix()},
    }

    with Popen([binadd_bin, "1", "2"], **popen_args) as P:
        assert P.stdout is not None
        stdout = P.stdout.read()
        lief.logging.info(stdout)
        assert re.search(r"LIEF is Working", stdout) is not None
