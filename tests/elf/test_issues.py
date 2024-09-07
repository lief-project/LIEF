#!/usr/bin/env python
import pytest

import lief
from pathlib import Path

from utils import get_sample, has_private_samples

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

def test_issue_1082():
    """
    Make sure RISC-V imported symbols are correctly exported
    """
    elf = lief.ELF.parse(get_sample("ELF/issue-1082-pie.elf"))
    imp_symbols = [s.name for s in elf.imported_symbols]
    assert len(imp_symbols) == 6
    assert imp_symbols[0] == "__libc_start_main"
    assert imp_symbols[1] == "printf"
    assert imp_symbols[2] == "__cxa_finalize"
    assert imp_symbols[3] == "__libc_start_main@GLIBC_2.34"
    assert imp_symbols[4] == "printf@GLIBC_2.27"
    assert imp_symbols[5] == "__cxa_finalize@GLIBC_2.27"

    elf = lief.ELF.parse(get_sample("ELF/issue-1082-no_pie.elf"))
    imp_symbols = [s.name for s in elf.imported_symbols]
    assert len(imp_symbols) == 4
    assert imp_symbols[0] == "printf"
    assert imp_symbols[2] == "__libc_start_main@GLIBC_2.34"
    assert imp_symbols[3] == "printf@GLIBC_2.27"

def test_issue_1089(tmp_path: Path):
    elf = lief.ELF.parse(get_sample("ELF/libip4tc.so.2.0.0"))

    original_nb_relocations = len(elf.dynamic_relocations)

    elf.remove_dynamic_symbol("iptc_read_counter")

    out = tmp_path / "libip4tc.so.2.0.0"
    elf.write(out.as_posix())

    new = lief.ELF.parse(out)

    assert new.get_symbol("iptc_read_counter") is None
    assert len(new.dynamic_relocations) == original_nb_relocations - 2

@pytest.mark.skipif(not has_private_samples(), reason="needs private samples")
def test_issue_1097(tmp_path: Path):
    elf = lief.ELF.parse(get_sample("private/ELF/libhwui.so"))
    deps = [entry.name for entry in elf.dynamic_entries if isinstance(entry, lief.ELF.DynamicEntryLibrary)]

    out = tmp_path / "libhwui.so"
    elf.write(out.as_posix())

    new = lief.ELF.parse(out)

    new_deps = [entry.name for entry in new.dynamic_entries if isinstance(entry, lief.ELF.DynamicEntryLibrary)]

    assert new_deps == deps
