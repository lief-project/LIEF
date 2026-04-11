# -*- coding: utf-8 -*-
import ctypes
import json
import os
import stat
from pathlib import Path

import lief
import pytest
from utils import get_sample, is_windows, parse_pe, win_exec

if is_windows():
    SEM_NOGPFAULTERRORBOX = 0x0002  # From MSDN
    ctypes.windll.kernel32.SetErrorMode(SEM_NOGPFAULTERRORBOX)  # type: ignore


def test_remove_section(tmp_path: Path):
    path = get_sample("PE/PE64_x86-64_remove_section.exe")
    sample = lief.parse(path)
    assert isinstance(sample, lief.PE.Binary)

    output = tmp_path / "section_removed.exe"

    sample.remove_section("lief")
    sample.write(output)

    st = os.stat(output)
    os.chmod(output, st.st_mode | stat.S_IEXEC)

    if ret := win_exec(output, gui=False):
        ret_code, stdout = ret
        assert "Hello World" in stdout


def test_unwind():

    path = get_sample("PE/PE64_x86-64_binary_cmd.exe")
    sample = lief.PE.parse(path, lief.PE.ParserConfig.all)
    assert sample is not None

    assert sample.original_size == Path(path).stat().st_size

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
    assert isinstance(pe, lief.PE.Binary)
    assert pe.get_section(".text") is not None
    assert pe.sections[0].name == ".text"
    assert pe.sections[0].fullname == b".text\x00\x00\x00"
    text = pe.sections[0]
    assert isinstance(text, lief.PE.Section)
    assert text.copy() == text
    text.name = ".foo"
    assert text.name == ".foo"
    lief.logging.info(text)


def test_utils():
    assert (
        lief.PE.get_type(get_sample("PE/PE32_x86_binary_PGO-LTCG.exe"))
        == lief.PE.PE_TYPE.PE32
    )
    assert (
        lief.PE.get_type(get_sample("ELF/ELF_Core_issue_808.core"))
        == lief.lief_errors.file_format_error
    )

    with open(get_sample("PE/PE32_x86_binary_PGO-LTCG.exe"), "rb") as f:
        buffer = list(f.read())
        assert lief.PE.get_type(buffer) == lief.PE.PE_TYPE.PE32


@pytest.mark.parametrize(
    "pe_file",
    [
        "PE/AcRes.dll",
        "PE/test.delay.exe",
        "PE/AppVClient.exe",
    ],
)
def test_json(pe_file):
    pe = lief.PE.parse(get_sample(pe_file))
    assert pe is not None
    out = lief.to_json(pe)
    assert out is not None
    assert len(out) > 0
    assert json.loads(out) is not None


def test_resolve_function():
    config = lief.PE.ParserConfig()
    config.parse_arm64x_binary = True
    pe = parse_pe("PE/win11_arm64x_Windows.Media.Protection.PlayReady.dll", config)
    assert pe is not None
    assert pe.get_function_address("BootstrapReleaseUnusedResources") == 0x00155C70

    nested = pe.nested_pe_binary
    assert nested is not None
    assert nested.get_function_address("BootstrapReleaseUnusedResources") == 0x00002000

    pe = parse_pe("PE/PE32_x86_binary_winhello-mingw.exe")
    assert pe.get_function_address("WinMainCRTStartup") == 0x4C0
