import subprocess
import sys
from pathlib import Path
from textwrap import dedent

import lief
import pytest
from utils import get_sample, parse_elf


def test_basic():
    sample = get_sample("ELF/ELF64_x86-64_binary_ls.bin")
    elf = lief.ELF.parse(sample)
    assert elf is not None
    res, err = lief.ELF.check_layout(elf)
    assert res, err


def test_corrupted_segment():
    sample = get_sample("ELF/ELF64_x86-64_binary_ls.bin")
    elf = lief.ELF.parse(sample)
    assert elf is not None
    # Corrupt a segment
    elf.segments[0].physical_size = 0xFFFFFFFF
    res, err = lief.ELF.check_layout(elf)
    assert not res
    assert "beyond file size" in err


def test_dynamic_relasz():
    sample = get_sample("ELF/ELF64_x86-64_binary_ls.bin")
    elf = lief.ELF.parse(sample)
    assert elf is not None
    # Find RELAENT and RELASZ
    relaent = 0
    relasz = 0
    for entry in elf.dynamic_entries:
        if entry.tag == lief.ELF.DynamicEntry.TAG.RELAENT:
            relaent = entry.value
        if entry.tag == lief.ELF.DynamicEntry.TAG.RELASZ:
            relasz = entry.value
    assert relasz > 0
    if relaent > 0:
        # Check that it passes originally
        res, err = lief.ELF.check_layout(elf)
        assert res, err

        # Corrupt RELAENT
        for entry in elf.dynamic_entries:
            if entry.tag == lief.ELF.DynamicEntry.TAG.RELAENT:
                entry.value = 7  # Invalid size
                break

        res, err = lief.ELF.check_layout(elf)
        assert not res
        assert (
            "DT_RELAENT" in err or "DT_RELASZ" in err
        )  # depending on which check hits first


def test_page_sharing():
    # This binary has a layout for 64KB pages: two PT_LOAD segments that end up
    # in the same 64KB page can't be mapped independently (cf. issue #1366)
    elf = parse_elf("ELF/hello_aarch64_attr")
    res, err = lief.ELF.check_layout(elf)
    assert res, err

    loads = [s for s in elf.segments if s.type == lief.ELF.Segment.TYPE.LOAD]

    assert loads[0].alignment == 0x10000
    assert loads[0].virtual_address + loads[0].virtual_size < 0x10000
    assert loads[1].virtual_address > 0x10000

    # Expand the first segment in the page of the second one. Note that both
    # are still disjoint in memory.
    loads[0].virtual_size = 0x10100

    res, err = lief.ELF.check_layout(elf)
    assert not res
    assert "share the same page" in err


def test_pt_phdr_wrap():
    sample = get_sample("ELF/ELF64_x86-64_binary_ls.bin")
    elf = lief.ELF.parse(sample)
    assert elf is not None
    pt_phdr = elf.get(lief.ELF.Segment.TYPE.PHDR)
    if pt_phdr is not None:
        # Move it outside any LOAD
        pt_phdr.virtual_address = 0xDEADBEEF000
        res, err = lief.ELF.check_layout(elf)
        assert not res
        assert "PT_PHDR segment is not wrapped" in err


@pytest.mark.private
def test_many_load_segments_perfs():
    sample = Path(get_sample("private/ELF/load_segments_scaling.elf")).absolute()

    code = dedent("""\
        import lief
        import sys
        elf = lief.ELF.parse(sys.argv[1])
        assert elf is not None
        assert len(elf.segments) == 8192
        elf.header.numberof_segments = 1
        valid, error = lief.ELF.check_layout(elf)
        assert valid, error""")

    subprocess.check_call([sys.executable, "-c", code, str(sample)], timeout=30)
