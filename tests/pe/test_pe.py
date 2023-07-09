#!/usr/bin/env python
# -*- coding: utf-8 -*-

import lief
import os
import sys
import stat
import subprocess
import ctypes
import json

from subprocess import Popen

from utils import get_sample

if sys.platform.startswith("win"):
    SEM_NOGPFAULTERRORBOX = 0x0002 # From MSDN
    ctypes.windll.kernel32.SetErrorMode(SEM_NOGPFAULTERRORBOX)

def test_code_view_pdb():
    path = get_sample('PE/PE64_x86-64_binary_ConsoleApplication1.exe')
    sample = lief.parse(path)

    assert sample.has_debug

    debug_code_view = list(filter(lambda deb: deb.has_code_view, sample.debug))
    assert len(debug_code_view) == 1

    debug = debug_code_view[0]
    code_view = debug.code_view

    assert code_view.cv_signature == lief.PE.CODE_VIEW_SIGNATURES.PDB_70
    assert code_view.signature == [245, 217, 227, 182, 71, 113, 1, 79, 162, 3, 170, 71, 124, 74, 186, 84]
    assert code_view.age == 1
    assert code_view.filename == r"c:\users\romain\documents\visual studio 2015\Projects\HelloWorld\x64\Release\ConsoleApplication1.pdb"

    json_view = json.loads(lief.to_json(debug))
    assert json_view == {
        'addressof_rawdata': 8996,
        'characteristics': 0,
        'code_view': {
            'age': 1,
            'cv_signature': 'PDB_70',
            'filename': 'c:\\users\\romain\\documents\\visual studio 2015\\Projects\\HelloWorld\\x64\\Release\\ConsoleApplication1.pdb',
            'signature': [245, 217, 227, 182, 71, 113, 1, 79, 162, 3, 170, 71, 124, 74, 186, 84]
        },
        'major_version': 0,
        'minor_version': 0,
        'pointerto_rawdata': 5412,
        'sizeof_data': 125,
        'timestamp': 1459952944,
        'type': 'CODEVIEW'
    }
    assert print(code_view) is None

def test_remove_section(tmp_path):
    path = get_sample('PE/PE64_x86-64_remove_section.exe')
    sample = lief.parse(path)

    output = tmp_path / "section_removed.exe"

    sample.remove_section("lief")
    sample.write(output.as_posix())

    st = os.stat(output)
    os.chmod(output, st.st_mode | stat.S_IEXEC)

    if sys.platform.startswith("win"):
        subprocess_flags = 0x8000000 # win32con.CREATE_NO_WINDOW?
        p = Popen([output.as_posix()], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=subprocess_flags)

        stdout, _ = p.communicate()
        stdout = stdout.decode("utf8")
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

def test_pgo():
    path   = get_sample("PE/PE32_x86_binary_PGO-LTCG.exe")
    sample = lief.parse(path)

    debugs = sample.debug
    assert len(debugs) == 3

    debug_entry = debugs[2]

    assert debug_entry.has_pogo
    pogo = debug_entry.pogo
    assert pogo.signature == lief.PE.POGO_SIGNATURES.LCTG

    pogo_entries = pogo.entries
    assert len(pogo_entries) == 33

    assert pogo_entries[23].name == ".xdata$x"
    assert pogo_entries[23].start_rva == 0x8200
    assert pogo_entries[23].size == 820


def test_sections():
    path = get_sample("PE/PE32_x86_binary_PGO-LTCG.exe")
    pe = lief.parse(path)
    assert pe.get_section(".text") is not None
    assert pe.sections[0].name == ".text"
    assert pe.sections[0].fullname.encode("utf8") == b".text\x00\x00\x00"

def test_utils():
    assert lief.PE.get_type(get_sample("PE/PE32_x86_binary_PGO-LTCG.exe")) == lief.PE.PE_TYPE.PE32
    assert lief.PE.get_type(get_sample("ELF/ELF_Core_issue_808.core")) == lief.lief_errors.file_format_error

    with open(get_sample("PE/PE32_x86_binary_PGO-LTCG.exe"), "rb") as f:
        buffer = list(f.read())
        assert lief.PE.get_type(buffer) == lief.PE.PE_TYPE.PE32

