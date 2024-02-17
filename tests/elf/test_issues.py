#!/usr/bin/env python
import pytest

import lief
from pathlib import Path

from utils import get_sample

def test_issue_863(tmp_path: Path):
    elf = lief.ELF.parse(get_sample('ELF/issue_863.elf'))

    assert elf.sysv_hash.nchain == 7

    elf.remove_dynamic_symbol("puts")

    out = tmp_path / "issue_863.modified"
    elf.write(out.as_posix())

    new = lief.ELF.parse(out.as_posix())
    assert new.sysv_hash.nchain == 6

def test_pr_968():
    elf = lief.ELF.parse(get_sample('ELF/echo.mips_r3000.bin'))
    sym: lief.ELF.Symbol = elf.get_symbol("strstr")
    assert sym.imported

def test_issue_1023():
    """
    Make sure that get_content_from_virtual_address return an empty
    buffer when trying to read bss segment
    """
    elf = lief.ELF.parse(get_sample('ELF/nopie_bss_671.elf'))

    bss_segment = elf.segments[3]
    bss_start = bss_segment.virtual_address + bss_segment.physical_size
    bss_content = elf.get_content_from_virtual_address(bss_start + 1, 1)

    assert len(bss_content) == 0
