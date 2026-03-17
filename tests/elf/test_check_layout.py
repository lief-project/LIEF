import lief
import pytest
from utils import get_sample

def test_basic():
    sample = get_sample('ELF/ELF64_x86-64_binary_ls.bin')
    elf = lief.ELF.parse(sample)
    res, err = lief.ELF.check_layout(elf)
    assert res, err

def test_corrupted_segment():
    sample = get_sample('ELF/ELF64_x86-64_binary_ls.bin')
    elf = lief.ELF.parse(sample)
    # Corrupt a segment
    elf.segments[0].physical_size = 0xFFFFFFFF
    res, err = lief.ELF.check_layout(elf)
    assert not res
    assert "beyond file size" in err

def test_dynamic_relasz():
    sample = get_sample('ELF/ELF64_x86-64_binary_ls.bin')
    elf = lief.ELF.parse(sample)

    # Find RELAENT and RELASZ
    relaent = 0
    relasz = 0
    for entry in elf.dynamic_entries:
        if entry.tag == lief.ELF.DynamicEntry.TAG.RELAENT:
            relaent = entry.value
        if entry.tag == lief.ELF.DynamicEntry.TAG.RELASZ:
            relasz = entry.value

    if relaent > 0:
        # Check that it passes originally
        res, err = lief.ELF.check_layout(elf)
        assert res, err

        # Corrupt RELAENT
        for entry in elf.dynamic_entries:
            if entry.tag == lief.ELF.DynamicEntry.TAG.RELAENT:
                entry.value = 7 # Invalid size
                break

        res, err = lief.ELF.check_layout(elf)
        assert not res
        assert "DT_RELAENT" in err or "DT_RELASZ" in err # depending on which check hits first

def test_pt_phdr_wrap():
    sample = get_sample('ELF/ELF64_x86-64_binary_ls.bin')
    elf = lief.ELF.parse(sample)

    pt_phdr = elf.get(lief.ELF.Segment.TYPE.PHDR)
    if pt_phdr is not None:
        # Move it outside any LOAD
        pt_phdr.virtual_address = 0xdeadbeef000
        res, err = lief.ELF.check_layout(elf)
        assert not res
        assert "PT_PHDR segment is not wrapped" in err
