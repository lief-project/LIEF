#!/usr/bin/env python

import subprocess
from subprocess import Popen
import pytest
import stat

import lief
import pathlib

from utils import get_sample, is_linux, is_x86_64

def test_issue_872(tmp_path):
    tmp = pathlib.Path(tmp_path)

    elf: lief.ELF.Binary = lief.ELF.parse(get_sample('ELF/i872_risv.elf'))
    payload_sec = elf.get_section(".payload")
    offset = payload_sec.offset

    new_section = lief.ELF.Section(".new_section")
    new_section.virtual_address = 0xa0000000
    new_section.add(lief.ELF.Section.FLAGS.ALLOC)
    new_section.size = 0x1000
    new_section.content = [0xa5] * 0x1000
    elf.add(new_section)

    outpath = tmp / "i872_risv_modified.elf"
    elf.write(outpath.as_posix())

    modified: lief.ELF.Binary = lief.ELF.parse(outpath.as_posix())
    new_offset = modified.get_section(".payload").offset

    new_section = modified.get_section(".new_section")
    new_segment = modified.segment_from_offset(new_section.offset)

    assert offset == new_offset

    assert new_section.virtual_address == 0xa0000000
    assert new_segment is not None
    assert new_segment.virtual_address == 0xa0000000

@pytest.mark.skipif(not (is_linux() and is_x86_64()), reason="incompatible env")
@pytest.mark.parametrize("mode", [
    lief.ELF.Binary.PHDR_RELOC.SEGMENT_GAP,
    lief.ELF.Binary.PHDR_RELOC.FILE_END,
    lief.ELF.Binary.PHDR_RELOC.BSS_END
])
def test_static_musl(tmp_path, mode):
    sample = get_sample("ELF/i872_hello_musl.elf")
    elf: lief.ELF.Binary = lief.ELF.parse(sample)
    elf.relocate_phdr_table(mode)

    segment = lief.ELF.Segment()
    segment.type = lief.ELF.Segment.TYPE.LOAD
    segment.content = [0xcc for _ in range(0x2000)]

    elf.add(segment)
    outpath = tmp_path / "modified.elf"
    elf.write(outpath.as_posix())
    outpath.chmod(outpath.stat().st_mode | stat.S_IEXEC)

    popen_args = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "universal_newlines": True
    }

    with Popen([outpath.as_posix()], **popen_args) as proc: # type: ignore
        stdout = proc.stdout.read()
        assert "Hello World" in stdout, f"Error: {stdout}"


@pytest.mark.skipif(not (is_linux() and is_x86_64()), reason="incompatible env")
@pytest.mark.parametrize("mode", [
    lief.ELF.Binary.PHDR_RELOC.SEGMENT_GAP,
    lief.ELF.Binary.PHDR_RELOC.FILE_END,
    lief.ELF.Binary.PHDR_RELOC.BSS_END
])
def test_static_musl_bss(tmp_path, mode):
    sample = get_sample("ELF/i872_hello_musl_bss.elf")
    elf: lief.ELF.Binary = lief.ELF.parse(sample)
    elf.relocate_phdr_table(mode)

    segment = lief.ELF.Segment()
    segment.type = lief.ELF.Segment.TYPE.LOAD
    segment.content = [0xcc for _ in range(0x2000)]

    elf.add(segment)
    outpath = tmp_path / "modified.elf"
    elf.write(outpath.as_posix())
    outpath.chmod(outpath.stat().st_mode | stat.S_IEXEC)

    popen_args = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "universal_newlines": True
    }

    with Popen([outpath.as_posix()], **popen_args) as proc: # type: ignore
        stdout = proc.stdout.read()
        assert "Hello World" in stdout, f"Error: {stdout}"

@pytest.mark.skipif(not (is_linux() and is_x86_64()), reason="incompatible env")
@pytest.mark.parametrize("mode", [
    lief.ELF.Binary.PHDR_RELOC.SEGMENT_GAP,
    lief.ELF.Binary.PHDR_RELOC.FILE_END,
    lief.ELF.Binary.PHDR_RELOC.BSS_END
])
def test_static(tmp_path, mode):
    sample = get_sample("ELF/i872_hello.elf")
    elf: lief.ELF.Binary = lief.ELF.parse(sample)
    elf.relocate_phdr_table(mode)

    segment = lief.ELF.Segment()
    segment.type = lief.ELF.Segment.TYPE.LOAD
    segment.content = [0xcc for _ in range(0x2000)]

    elf.add(segment)
    outpath = tmp_path / "modified.elf"
    elf.write(outpath.as_posix())
    outpath.chmod(outpath.stat().st_mode | stat.S_IEXEC)

    popen_args = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "universal_newlines": True
    }

    with Popen([outpath.as_posix()], **popen_args) as proc: # type: ignore
        stdout = proc.stdout.read()
        assert "Hello World" in stdout, f"Error: {stdout}"


@pytest.mark.skipif(not (is_linux() and is_x86_64()), reason="incompatible env")
@pytest.mark.parametrize("mode", [
    lief.ELF.Binary.PHDR_RELOC.SEGMENT_GAP,
    lief.ELF.Binary.PHDR_RELOC.FILE_END,
    lief.ELF.Binary.PHDR_RELOC.BSS_END
])
def test_static_bss(tmp_path, mode):
    sample = get_sample("ELF/i872_hello_bss.elf")
    elf: lief.ELF.Binary = lief.ELF.parse(sample)
    elf.relocate_phdr_table(mode)

    segment = lief.ELF.Segment()
    segment.type = lief.ELF.Segment.TYPE.LOAD
    segment.content = [0xcc for _ in range(0x2000)]

    elf.add(segment)
    outpath = tmp_path / "modified.elf"
    elf.write(outpath.as_posix())
    outpath.chmod(outpath.stat().st_mode | stat.S_IEXEC)

    popen_args = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "universal_newlines": True
    }

    with Popen([outpath.as_posix()], **popen_args) as proc: # type: ignore
        stdout = proc.stdout.read()
        assert "Hello World" in stdout, f"Error: {stdout}"

@pytest.mark.skipif(not (is_linux() and is_x86_64()), reason="incompatible env")
@pytest.mark.parametrize("mode", [
    lief.ELF.Binary.PHDR_RELOC.SEGMENT_GAP,
    lief.ELF.Binary.PHDR_RELOC.FILE_END,
    lief.ELF.Binary.PHDR_RELOC.BSS_END
])
def test_docker_init(tmp_path, mode):
    sample = get_sample("ELF/docker-init.elf")
    elf: lief.ELF.Binary = lief.ELF.parse(sample)
    elf.relocate_phdr_table(mode)

    segment = lief.ELF.Segment()
    segment.type = lief.ELF.Segment.TYPE.LOAD
    segment.content = [0xcc for _ in range(0x2000)]

    elf.add(segment)
    outpath = tmp_path / "modified.elf"
    elf.write(outpath.as_posix())
    outpath.chmod(outpath.stat().st_mode | stat.S_IEXEC)

    popen_args = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "universal_newlines": True
    }

    with Popen([outpath.as_posix(), "--version"], **popen_args) as proc: # type: ignore
        stdout = proc.stdout.read()
        assert "tini version 0.19.0" in stdout, f"Error: {stdout}"
