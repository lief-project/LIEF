#!/usr/bin/env python
import os
import re
import stat
import subprocess
import pytest
from subprocess import Popen
from pathlib import Path

import lief
from lief.ELF import Segment
from utils import get_sample, has_recent_glibc, is_linux, is_x86_64, is_aarch64

is_updated_linux = pytest.mark.skipif(not (is_linux() and is_x86_64() and has_recent_glibc()),
                                      reason="needs a recent x86-64 Linux system")

is_linux_x64 = pytest.mark.skipif(not (is_linux() and is_x86_64()), reason="needs a Linux x86-64")

lief.logging.set_level(lief.logging.LEVEL.INFO)

CWD = Path(__file__).parent

@is_updated_linux
def test_simple(tmp_path: Path):
    sample_path = get_sample('ELF/ELF64_x86-64_binary_ls.bin')
    stub        = lief.ELF.parse((CWD / "hello_lief.bin").as_posix())
    output      = tmp_path / "ls.segment"

    target = lief.ELF.parse(sample_path)
    for _ in range(4):
        segment                 = stub.segments[0]
        original_va             = segment.virtual_address
        segment.virtual_address = 0
        segment                 = target.add(segment)
        new_ep                  = (stub.header.entrypoint - original_va) + segment.virtual_address
        target.header.entrypoint = new_ep

    target.write(output.as_posix())

    st = os.stat(output)
    os.chmod(output, st.st_mode | stat.S_IEXEC)

    with Popen(output.as_posix(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as P:
        stdout = P.stdout.read().decode("utf8")
        print(stdout)
        assert re.search(r'LIEF is Working', stdout) is not None

@is_updated_linux
def test_gcc(tmp_path: Path):
    sample_path = get_sample('ELF/ELF64_x86-64_binary_gcc.bin')
    stub        = lief.ELF.parse((CWD / "hello_lief.bin").as_posix())
    output      = tmp_path / "gcc.segment"

    target                  = lief.ELF.parse(sample_path)
    segment                 = stub.segments[0]
    original_va             = segment.virtual_address
    segment.virtual_address = 0
    segment                 = target.add(segment)
    new_ep                  = (stub.header.entrypoint - original_va) + segment.virtual_address

    target.header.entrypoint = new_ep
    target.write(output.as_posix())

    st = os.stat(output)
    os.chmod(output, st.st_mode | stat.S_IEXEC)

    with Popen(output.as_posix(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as P:
        stdout = P.stdout.read().decode("utf8")
        print(stdout)
        assert re.search(r'LIEF is Working', stdout) is not None

@is_linux_x64
def test_static(tmp_path: Path):
    sample_path = get_sample('ELF/ELF64_x86-64_binary_static-binary.bin')
    stub        = lief.ELF.parse((CWD / "hello_lief.bin").as_posix())
    output      = tmp_path / "static.segment"

    target                  = lief.ELF.parse(sample_path)
    segment                 = stub.segments[0]
    original_va             = segment.virtual_address
    segment.virtual_address = 0
    segment                 = target.add(segment)
    new_ep                  = (stub.header.entrypoint - original_va) + segment.virtual_address

    target.header.entrypoint = new_ep
    target.write(output.as_posix())

    st = os.stat(output)
    os.chmod(output, st.st_mode | stat.S_IEXEC)

    with Popen(output.as_posix(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as P:
        stdout = P.stdout.read().decode("utf8")
        print(stdout)
        assert re.search(r'LIEF is Working', stdout) is not None


@pytest.mark.skipif(not is_linux(), reason="needs a Linux system")
@pytest.mark.parametrize("binpath", [
    '/usr/bin/ls',      '/bin/ls',
    '/usr/bin/ssh',     '/usr/bin/nm',
    '/usr/bin/openssl', '/usr/bin/bc',
    '/usr/bin/bzip2',   '/bin/bzip2',
    '/usr/bin/cp',      '/bin/cp',
    '/usr/bin/find',    '/usr/bin/file',
])
def test_add_segment(tmp_path: Path, binpath):
    target = Path(binpath)
    if not target.is_file():
        print(f"{target} does not exists. Skip!")
        return

    stub = None
    if is_x86_64():
        stub = lief.ELF.parse((CWD / "hello_lief.bin").as_posix())
    elif is_aarch64():
        stub = lief.ELF.parse((CWD / "hello_lief_aarch64.bin").as_posix())

    name = target.name
    elf = lief.ELF.parse(target.as_posix())
    output = tmp_path / f"{name}.segment"
    for _ in range(6):
        stub_segment      = stub.segments[0]
        segment           = lief.ELF.Segment()
        segment.content   = stub.segments[0].content
        segment.type      = stub_segment.type
        segment.alignment = stub_segment.alignment
        segment.flags     = stub_segment.flags

        new_segment       = elf.add(segment)
        new_ep            = (stub.header.entrypoint - stub.imagebase - stub_segment.file_offset) + new_segment.virtual_address

        elf.header.entrypoint = new_ep
    elf.write(output.as_posix())

    st = os.stat(output)
    os.chmod(output, st.st_mode | stat.S_IEXEC)

    with Popen(output.as_posix(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as P:
        stdout = P.stdout.read().decode("utf8")
        print(stdout)
        assert re.search(r'LIEF is Working', stdout) is not None
