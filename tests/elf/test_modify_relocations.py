#!/usr/bin/env python
import os
import stat
import re
import subprocess
from pathlib import Path
from subprocess import Popen

import lief

from utils import get_sample, has_recent_glibc, is_linux, is_x86_64

is_updated_linux = is_linux() and is_x86_64() and has_recent_glibc()
is_linux_x64 = is_linux() and is_x86_64()

def test_simple(tmp_path: Path):
    sample_path = get_sample('ELF/ELF64_x86-64_binary_ls.bin')
    output      = tmp_path / "ls.relocation"

    ls = lief.parse(sample_path)

    relocation = lief.ELF.Relocation(0x61D370, type=lief.ELF.RELOCATION_X86_64.JUMP_SLOT, is_rela=True)

    symbol = lief.ELF.Symbol()
    symbol.name = "printf123"

    relocation.symbol = symbol

    ls.add_pltgot_relocation(relocation)

    ls.write(output.as_posix())

    if is_updated_linux:
        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        with Popen([output, "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as P:
            stdout = P.stdout.read().decode("utf8")
            print(stdout)
            assert re.search(r'ls \(GNU coreutils\) ', stdout) is not None

def test_all(tmp_path: Path):
    sample_path = get_sample('ELF/ELF64_x86-64_binary_all.bin')
    output      = tmp_path / "all.relocation"

    target = lief.parse(sample_path)

    relocation = lief.ELF.Relocation(0x201028, type=lief.ELF.RELOCATION_X86_64.JUMP_SLOT, is_rela=True)

    symbol = lief.ELF.Symbol()
    symbol.name = "printf123"

    relocation.symbol = symbol
    target.add_pltgot_relocation(relocation)

    target.write(output.as_posix())

    if is_linux_x64:
        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        with Popen([output], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as P:
            stdout = P.stdout.read().decode("utf8")
            print(stdout)
            assert re.search(r'Hello World: 1', stdout) is not None


def test_all32(tmp_path: Path):
    sample_path = get_sample('ELF/ELF32_x86_binary_all.bin')
    output      = tmp_path / "all32.relocation"

    target = lief.parse(sample_path)

    relocation = lief.ELF.Relocation(0x2018, type=lief.ELF.RELOCATION_i386.JUMP_SLOT, is_rela=False)

    symbol = lief.ELF.Symbol()
    symbol.name = "printf123"

    relocation.symbol = symbol
    target.add_pltgot_relocation(relocation)

    target.write(output.as_posix())

    new = lief.parse(output.as_posix())
    assert new.has_symbol("printf123")
