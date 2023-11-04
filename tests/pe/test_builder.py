#!/usr/bin/env python

import lief
import os
import stat
import ctypes
import zipfile

from utils import get_sample, is_windows, win_exec

if is_windows():
    SEM_NOGPFAULTERRORBOX = 0x0002  # From MSDN
    ctypes.windll.kernel32.SetErrorMode(SEM_NOGPFAULTERRORBOX)

def test_add_multiples_sections(tmp_path):
    sample_file = get_sample('PE/PE32_x86_binary_Notepad++.zip')
    sample_dir  = tmp_path / "Notepad++"

    sample = sample_dir / "notepad++.exe"
    output = sample_dir / "notepad++_sections.exe"

    with zipfile.ZipFile(sample_file, 'r') as zip_ref:
        zip_ref.extractall(tmp_path)

    notepadpp = lief.PE.parse(sample.as_posix())

    # Add 20 sections to the binary
    for i in range(20):
        section = lief.PE.Section(f".section_{i}")
        section.content = [i & 0xFF for i in range(0x200)]
        notepadpp.add_section(section)

    builder = lief.PE.Builder(notepadpp)
    builder.build()

    builder.write(output.as_posix())

    st = os.stat(output)
    os.chmod(output, st.st_mode | stat.S_IEXEC)

    if ret := win_exec(output):
        ret_code, stdout = ret
        assert ret_code == 0

def test_imports_notepadpp(tmp_path):
    sample_file = get_sample('PE/PE32_x86_binary_Notepad++.zip')
    sample_dir  = tmp_path / "Notepad++"

    sample = sample_dir / "notepad++.exe"
    output = sample_dir / "notepad++_imports.exe"

    with zipfile.ZipFile(sample_file, 'r') as zip_ref:
        zip_ref.extractall(tmp_path)

    notepadpp = lief.parse(sample.as_posix())

    # Disable ASLR
    notepadpp.optional_header.dll_characteristics &= ~lief.PE.OptionalHeader.DLL_CHARACTERISTICS.DYNAMIC_BASE

    # Disable NX protection
    notepadpp.optional_header.dll_characteristics &= ~lief.PE.OptionalHeader.DLL_CHARACTERISTICS.NX_COMPAT

    builder = lief.PE.Builder(notepadpp)
    builder.build_imports(True).patch_imports(True)
    builder.build()

    builder.write(output.as_posix())

    st = os.stat(output)
    os.chmod(output, st.st_mode | stat.S_IEXEC)

    if ret := win_exec(output):
        ret_code, stdout = ret
        assert ret_code == 0

def test_issue_952(tmp_path):
    pe = lief.PE.parse(get_sample("PE/PE32_x86_binary_HelloWorld.exe"))
    stub = bytes(pe.dos_stub)
    assert not all(x == 0 for x in stub)

    out = tmp_path / "out.exe"
    pe.write(out.as_posix())

    new = lief.PE.parse(out.as_posix())
    assert bytes(new.dos_stub) == stub
