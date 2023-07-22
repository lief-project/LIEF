#!/usr/bin/env python
# -*- coding: utf-8 -*-
import ctypes
import json
import lief
import os
import pytest
import stat
import subprocess

from subprocess import Popen

from utils import get_sample, is_windows

if is_windows():
    SEM_NOGPFAULTERRORBOX = 0x0002  # From MSDN
    ctypes.windll.kernel32.SetErrorMode(SEM_NOGPFAULTERRORBOX)

def test_remove_section(tmp_path):
    path = get_sample('PE/PE64_x86-64_remove_section.exe')
    sample = lief.parse(path)

    output = tmp_path / "section_removed.exe"

    sample.remove_section("lief")
    sample.write(output.as_posix())

    st = os.stat(output)
    os.chmod(output, st.st_mode | stat.S_IEXEC)

    if is_windows():
        popen_args = {
            "shell": True,
            "universal_newlines": True,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT,
            "creationflags": 0x8000000  # win32con.CREATE_NO_WINDOW
        }
        with Popen([output.as_posix()], **popen_args) as proc:
            stdout, _ = proc.communicate()
            print(stdout)
            assert "Hello World" in stdout

def test_unwind():

    path = get_sample("PE/PE64_x86-64_binary_cmd.exe")
    sample = lief.parse(path)

    functions = sorted(sample.functions, key=lambda f: f.address)

    assert len(functions) == 829

    assert functions[0].address == 4160
    assert functions[0].size == 107
    assert functions[0].name == ""

    assert functions[-1].address == 163896
    assert functions[-1].size == 54
    assert functions[-1].name == ""

def test_sections():
    path = get_sample("PE/PE32_x86_binary_PGO-LTCG.exe")
    pe = lief.parse(path)
    assert pe.get_section(".text") is not None
    assert pe.sections[0].name == ".text"
    assert pe.sections[0].fullname.encode("utf8") == b".text\x00\x00\x00"
    text = pe.sections[0]
    assert text.copy() == text
    text.name = ".foo"
    assert text.name == ".foo"
    print(text)

def test_utils():
    assert lief.PE.get_type(get_sample("PE/PE32_x86_binary_PGO-LTCG.exe")) == lief.PE.PE_TYPE.PE32
    assert lief.PE.get_type(get_sample("ELF/ELF_Core_issue_808.core")) == lief.lief_errors.file_format_error

    with open(get_sample("PE/PE32_x86_binary_PGO-LTCG.exe"), "rb") as f:
        buffer = list(f.read())
        assert lief.PE.get_type(buffer) == lief.PE.PE_TYPE.PE32

@pytest.mark.parametrize("pe_file", [
    "PE/AcRes.dll",
    "PE/test.delay.exe",
    "PE/AppVClient.exe",
])
def test_json(pe_file):
    pe = lief.PE.parse(get_sample(pe_file))
    print(pe)
    out = lief.to_json(pe)
    assert out is not None
    assert len(out) > 0
    assert json.loads(out) is not None
