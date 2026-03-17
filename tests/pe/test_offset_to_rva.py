#!/usr/bin/env python
import lief
from utils import get_sample

def test_offset_to_rva():
    path = get_sample("PE/PE64_x86-64_binary_cmd.exe")
    pe = lief.PE.parse(path)

    section_text = pe.get_section(".text")
    assert section_text is not None

    offset = section_text.pointerto_raw_data + 0x100
    rva = pe.offset_to_rva(offset)
    expected_rva = section_text.virtual_address + 0x100

    assert rva == expected_rva
    assert pe.rva_to_offset(rva) == offset

    va = rva + pe.optional_header.imagebase
    assert pe.va_to_offset(va) == offset

def test_offset_to_va():
    path = get_sample("PE/PE64_x86-64_binary_cmd.exe")
    pe = lief.PE.parse(path)

    section_text = pe.get_section(".text")
    assert section_text is not None

    offset = section_text.pointerto_raw_data + 0x100
    va = pe.offset_to_virtual_address(offset)
    expected_va = pe.optional_header.imagebase + section_text.virtual_address + 0x100

    assert va == expected_va

    slide = 0x10000000
    va_slide = pe.offset_to_virtual_address(offset, slide)
    assert va_slide == slide + section_text.virtual_address + 0x100
