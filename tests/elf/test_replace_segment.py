import os
import re
import stat
import subprocess
from pathlib import Path
from subprocess import Popen

import lief
import pytest
from utils import (
    check_layout,
    get_sample,
    has_recent_glibc,
    is_aarch64,
    is_linux,
    is_x86_64,
)

is_updated_linux = is_linux() and is_x86_64() and has_recent_glibc()

CWD = Path(__file__).parent


def test_simple(tmp_path: Path):
    sample_path = get_sample("ELF/ELF64_x86-64_binary_ls.bin")
    stub = lief.ELF.parse(CWD / "hello_lief.bin")
    assert stub is not None
    output = tmp_path / "ls.replace_segment"
    target = lief.ELF.parse(sample_path)
    assert target is not None

    assert lief.ELF.Segment.TYPE.NOTE in target

    segment = stub.segments[0]
    original_va = segment.virtual_address
    segment.virtual_address = 0
    note_segment = target[lief.ELF.Segment.TYPE.NOTE]
    assert note_segment is not None
    segment = target.replace(segment, note_segment)
    assert segment is not None
    new_ep = (stub.header.entrypoint - original_va) + segment.virtual_address

    target.header.entrypoint = new_ep
    target.write(output)

    check_layout(output)

    if is_updated_linux:
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
    sample_path = get_sample("ELF/ELF64_x86-64_binary_gcc.bin")
    stub = lief.ELF.parse(CWD / "hello_lief.bin")
    assert stub is not None
    output = tmp_path / "gcc.replace_segment"
    target = lief.ELF.parse(sample_path)
    assert target is not None

    assert lief.ELF.Segment.TYPE.NOTE in target

    segment = stub.segments[0]
    original_va = segment.virtual_address
    segment.virtual_address = 0
    note_segment = target[lief.ELF.Segment.TYPE.NOTE]
    assert note_segment is not None
    segment = target.replace(segment, note_segment)
    assert segment is not None
    new_ep = (stub.header.entrypoint - original_va) + segment.virtual_address

    target.header.entrypoint = new_ep
    target.write(output)

    check_layout(output)

    if is_updated_linux:
        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        with Popen(
            output.as_posix(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        ) as P:
            assert P.stdout is not None
            stdout = P.stdout.read().decode("utf8")
            lief.logging.info(stdout)
            assert re.search(r"LIEF is Working", stdout) is not None


@pytest.mark.linux
@pytest.mark.skipif(not os.path.isfile("/usr/bin/ssh"), reason="missing '/usr/bin/ssh'")
def test_ssh(tmp_path: Path):
    stub = None
    if is_x86_64():
        stub = lief.ELF.parse(CWD / "hello_lief.bin")
    elif is_aarch64():
        stub = lief.ELF.parse(CWD / "hello_lief_aarch64.bin")

    output = tmp_path / "ssh.replace_segment"
    target = lief.ELF.parse("/usr/bin/ssh")
    assert stub is not None
    assert target is not None

    assert lief.ELF.Segment.TYPE.NOTE in target

    segment = stub.segments[0]
    original_va = segment.virtual_address
    segment.virtual_address = 0
    note_segment = target[lief.ELF.Segment.TYPE.NOTE]
    assert note_segment is not None
    segment = target.replace(segment, note_segment)
    assert segment is not None
    new_ep = (stub.header.entrypoint - original_va) + segment.virtual_address

    target.header.entrypoint = new_ep
    target.write(output)

    # check_layout(output)

    if is_linux() and has_recent_glibc():
        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        with Popen(
            output.as_posix(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        ) as P:
            assert P.stdout is not None
            stdout = P.stdout.read().decode("utf8")
            lief.logging.info(stdout)
            assert re.search(r"LIEF is Working", stdout) is not None
