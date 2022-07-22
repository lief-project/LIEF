#!/usr/bin/env python
import stat
import re
import subprocess
from subprocess import Popen
import pytest

import lief
import pathlib

from utils import get_sample, has_recent_glibc, is_linux, is_x86_64

@pytest.mark.skipif(not (is_linux() and is_x86_64() and has_recent_glibc()), reason="incompatible env")
def test_freebl(tmp_path):
    tmp = pathlib.Path(tmp_path)

    libfreebl3_path   = get_sample('ELF/ELF64_x86-64_library_libfreebl3.so')

    output_ls         = tmp / "ls.new"
    output_libfreebl3 = tmp / "libfreebl3.so"

    libfreebl3 = lief.parse(libfreebl3_path)
    ls         = lief.parse("/usr/bin/ls")
    if ls is None:
        ls = lief.parse("/bin/ls")

    if lief.ELF.DYNAMIC_TAGS.FLAGS_1 in ls and ls[lief.ELF.DYNAMIC_TAGS.FLAGS_1].has(lief.ELF.DYNAMIC_FLAGS_1.PIE):
        ls[lief.ELF.DYNAMIC_TAGS.FLAGS_1].remove(lief.ELF.DYNAMIC_FLAGS_1.PIE)

    ls.add_library("libfreebl3.so")

    ls         += lief.ELF.DynamicEntryRunPath("$ORIGIN")
    libfreebl3 += lief.ELF.DynamicEntryRunPath("$ORIGIN")

    ls.write(output_ls.as_posix())
    libfreebl3.write(output_libfreebl3.as_posix())

    output_ls.chmod(output_ls.stat().st_mode | stat.S_IEXEC)
    output_libfreebl3.chmod(output_libfreebl3.stat().st_mode | stat.S_IEXEC)
    with Popen([output_ls, "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
        stdout = proc.stdout.read()
        print(stdout.decode("utf8"))
        assert re.search(r'ls \(GNU coreutils\) ', stdout.decode("utf8")) is not None
