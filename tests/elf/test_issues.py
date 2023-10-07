#!/usr/bin/env python
import pytest

import lief
from pathlib import Path

from utils import get_sample

def test_issue_863(tmp_path: Path):
    elf = lief.parse(get_sample('ELF/issue_863.elf'))

    assert elf.sysv_hash.nchain == 7

    elf.remove_dynamic_symbol("puts")

    out = tmp_path / "issue_863.modified"
    elf.write(out.as_posix())

    new = lief.parse(out.as_posix())
    assert new.sysv_hash.nchain == 6

def test_pr_968():
    elf = lief.ELF.parse(get_sample('ELF/echo.mips_r3000.bin'))
    sym: lief.ELF.Symbol = elf.get_symbol("strstr")
    assert sym.imported
