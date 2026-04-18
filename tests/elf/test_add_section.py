import os
import re
import stat
import subprocess
from functools import lru_cache
from pathlib import Path
from subprocess import Popen

import lief
from utils import (
    check_layout,
    get_sample,
    glibc_version,
    is_aarch64,
    is_linux,
    is_x86_64,
)

CWD = Path(__file__).parent


@lru_cache
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


def test_simple(tmp_path: Path):
    stub = _get_stub()
    sample_path = get_sample("ELF/ELF64_x86-64_binary_ls.bin")
    output = tmp_path / "ls.section"

    ls = lief.ELF.parse(sample_path)
    assert ls is not None
    for i in range(10):
        section = lief.ELF.Section(f".test.{i}", lief.ELF.Section.TYPE.PROGBITS)
        section += lief.ELF.Section.FLAGS.EXECINSTR
        section += lief.ELF.Section.FLAGS.WRITE
        section.content = stub.segments[
            0
        ].content  # First LOAD segment which holds payload
        if i % 2 == 0:
            section = ls.add(section, loaded=True)
            assert section is not None
            ls.header.entrypoint = section.virtual_address + stub.header.entrypoint
        else:
            section = ls.add(section, loaded=False)
            assert section is not None

    ls.write(output)
    check_layout(output)

    if is_linux() and is_x86_64() and glibc_version() >= (2, 30):
        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        with Popen(
            output.as_posix(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        ) as P:
            assert P.stdout is not None
            stdout = P.stdout.read().decode("utf8")
            lief.logging.info(stdout)
            assert re.search(r"LIEF is Working", stdout) is not None


def test_gcc(tmp_path: Path):
    stub = _get_stub()
    sample_path = get_sample("ELF/ELF64_x86-64_binary_gcc.bin")
    output = tmp_path / "gcc.section"

    gcc = lief.ELF.parse(sample_path)
    assert gcc is not None
    for i in range(10):
        section = lief.ELF.Section(f".test.{i}", lief.ELF.Section.TYPE.PROGBITS)
        section.type = lief.ELF.Section.TYPE.PROGBITS
        section += lief.ELF.Section.FLAGS.EXECINSTR
        section += lief.ELF.Section.FLAGS.WRITE
        section.content = stub.segments[
            0
        ].content  # First LOAD segment which holds payload

        if i % 2 == 0:
            section = gcc.add(section, loaded=True)
            assert section is not None
            gcc.header.entrypoint = section.virtual_address + stub.header.entrypoint
        else:
            section = gcc.add(section, loaded=False)
            assert section is not None

    gcc.write(output)
    check_layout(output)

    if is_linux() and is_x86_64() and glibc_version() >= (2, 30):
        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        with Popen(
            output.as_posix(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        ) as P:
            assert P.stdout is not None
            stdout = P.stdout.read().decode("utf8")
            lief.logging.info(stdout)
            assert re.search(r"LIEF is Working", stdout) is not None
