#!/usr/bin/env python
import os
import re
import stat
import subprocess
import sys
import pytest
from subprocess import Popen
from pathlib import Path

import lief
from utils import get_sample, has_recent_glibc, is_linux, is_x86_64, is_aarch64

lief.logging.set_level(lief.logging.LEVEL.INFO)

is_updated_linux = is_linux() and is_x86_64() and has_recent_glibc()
is_linux_x64 = is_linux() and is_x86_64()

CWD = Path(__file__).parent

def test_simple(tmp_path: Path):
    sample_path = get_sample('ELF/ELF64_x86-64_binary_ls.bin')
    stub        = lief.ELF.parse((CWD / "hello_lief.bin").as_posix())
    output      = tmp_path / "ls.replace_segment"
    target      = lief.ELF.parse(sample_path)


    if not lief.ELF.Segment.TYPE.NOTE in target:
        print("Note not found!", file=sys.stderr)
        return

    segment                 = stub.segments[0]
    original_va             = segment.virtual_address
    segment.virtual_address = 0
    segment                 = target.replace(segment, target[lief.ELF.Segment.TYPE.NOTE])
    new_ep                  = (stub.header.entrypoint - original_va) + segment.virtual_address

    target.header.entrypoint = new_ep
    target.write(output.as_posix())

    if is_updated_linux:
        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        with Popen(output.as_posix(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as P:
            stdout = P.stdout.read().decode("utf8")
            print(stdout)
            assert re.search(r'LIEF is Working', stdout) is not None

def test_gcc(tmp_path: Path):
    sample_path = get_sample('ELF/ELF64_x86-64_binary_gcc.bin')
    stub        = lief.ELF.parse((CWD / "hello_lief.bin").as_posix())
    output      = tmp_path / "gcc.replace_segment"
    target      = lief.ELF.parse(sample_path)

    if not lief.ELF.Segment.TYPE.NOTE in target:
        print("Note not found!", file=sys.stderr)
        return

    segment                 = stub.segments[0]
    original_va             = segment.virtual_address
    segment.virtual_address = 0
    segment                 = target.replace(segment, target[lief.ELF.Segment.TYPE.NOTE])
    new_ep                  = (stub.header.entrypoint - original_va) + segment.virtual_address

    target.header.entrypoint = new_ep
    target.write(output.as_posix())

    if is_updated_linux:
        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        with Popen(output.as_posix(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as P:
            stdout = P.stdout.read().decode("utf8")
            print(stdout)
            assert re.search(r'LIEF is Working', stdout) is not None

@pytest.mark.skipif(not is_linux(), reason="requires Linux")
@pytest.mark.skipif(not Path('/usr/bin/ssh').is_file(), reason="missing '/usr/bin/ssh'")
def test_ssh(tmp_path: Path):
    stub = None
    if is_x86_64():
        stub = lief.ELF.parse((CWD / "hello_lief.bin").as_posix())
    elif is_aarch64():
        stub = lief.ELF.parse((CWD / "hello_lief_aarch64.bin").as_posix())

    output = tmp_path / "ssh.replace_segment"
    target = lief.ELF.parse("/usr/bin/ssh")

    if not lief.ELF.Segment.TYPE.NOTE in target:
        print("Note not found!", file=sys.stderr)
        return

    segment                 = stub.segments[0]
    original_va             = segment.virtual_address
    segment.virtual_address = 0
    segment                 = target.replace(segment, target[lief.ELF.Segment.TYPE.NOTE])
    new_ep                  = (stub.header.entrypoint - original_va) + segment.virtual_address

    target.header.entrypoint = new_ep
    target.write(output.as_posix())

    if is_linux() and has_recent_glibc():
        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        with Popen(output.as_posix(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as P:
            stdout = P.stdout.read().decode("utf8")
            print(stdout)
            assert re.search(r'LIEF is Working', stdout) is not None
