#!/usr/bin/env python
import os
import stat
import re
import subprocess
import pytest
from subprocess import Popen
from pathlib import Path

import lief

from utils import get_sample, has_recent_glibc, is_linux, is_x86_64, is_aarch64

CWD = Path(__file__).parent

STUB_FILE = None
if is_x86_64():
    STUB_FILE = "hello_lief.bin"
elif is_aarch64():
    STUB_FILE = "hello_lief_aarch64.bin"

STUB = lief.ELF.parse((CWD / STUB_FILE).as_posix())

is_updated_linux = pytest.mark.skipif(not (is_linux() and is_x86_64() and has_recent_glibc()),
                                      reason="needs a recent system")
@is_updated_linux
def test_simple(tmp_path: Path):
    sample_path = get_sample('ELF/ELF64_x86-64_binary_ls.bin')
    output      = tmp_path / "ls.section"

    ls = lief.ELF.parse(sample_path)
    for i in range(10):
        section = lief.ELF.Section(f".test.{i}", lief.ELF.Section.TYPE.PROGBITS)
        section += lief.ELF.Section.FLAGS.EXECINSTR
        section += lief.ELF.Section.FLAGS.WRITE
        section.content = STUB.segments[0].content # First LOAD segment which holds payload
        if i % 2 == 0:
            section = ls.add(section, loaded=True)
            ls.header.entrypoint = section.virtual_address + STUB.header.entrypoint
        else:
            section = ls.add(section, loaded=False)

    ls.write(output.as_posix())

    st = os.stat(output)
    os.chmod(output, st.st_mode | stat.S_IEXEC)

    with Popen(output.as_posix(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as P:
        stdout = P.stdout.read().decode("utf8")
        print(stdout)
        assert re.search(r'LIEF is Working', stdout) is not None


@is_updated_linux
def test_gcc(tmp_path):
    sample_path = get_sample('ELF/ELF64_x86-64_binary_gcc.bin')
    output      = tmp_path / "gcc.section"

    gcc = lief.ELF.parse(sample_path)
    for i in range(10):
        section = lief.ELF.Section(f".test.{i}", lief.ELF.Section.TYPE.PROGBITS)
        section.type     = lief.ELF.Section.TYPE.PROGBITS
        section         += lief.ELF.Section.FLAGS.EXECINSTR
        section         += lief.ELF.Section.FLAGS.WRITE
        section.content  = STUB.segments[0].content # First LOAD segment which holds payload

        if i % 2 == 0:
            section = gcc.add(section, loaded=True)
            gcc.header.entrypoint = section.virtual_address + STUB.header.entrypoint
        else:
            section = gcc.add(section, loaded=False)

    gcc.write(output.as_posix())

    st = os.stat(output)
    os.chmod(output, st.st_mode | stat.S_IEXEC)

    with Popen(output.as_posix(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as P:
        stdout = P.stdout.read().decode("utf8")
        print(stdout)
        assert re.search(r'LIEF is Working', stdout) is not None
