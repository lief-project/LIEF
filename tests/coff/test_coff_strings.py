from textwrap import dedent

import lief
import pytest
from utils import get_sample, parse_coff


@pytest.mark.private
def test_string_table_offset_overflow():
    coff = parse_coff("private/COFF/coff_strtab_overflow.obj")
    assert coff.sections[0].name == "/18"
    assert coff.sections[0].coff_string is None

    pristine = parse_coff("COFF/dwarf.obj")
    assert pristine.sections[0].coff_string is not None
    assert pristine.sections[0].coff_string.string == ".debug_rnglists"


def test_coff_sec_string():
    assert lief.is_coff(get_sample("COFF/dwarf.obj"))
    coff = parse_coff("COFF/dwarf.obj")

    section = coff.sections[0]
    _coff_str = section.coff_string
    assert _coff_str is not None
    assert _coff_str.string == ".debug_rnglists"
    assert (
        str(section)
        == dedent("""\
        Name:                    /18 (2f 31 38 00 00 00 00 00, .debug_rnglists)
        Virtual Size             0x0
        Virtual Address          0x0
        Size of raw data         0x21
        Pointer to raw data      0xb4
        Range                    [0x000000b4, 0x000000d5]
        Pointer to relocations   0x0
        Pointer to line numbers  0x0
        Number of relocations    0x0
        Number of lines          0x0
        Characteristics          CNT_INITIALIZED_DATA, ALIGN_1BYTES, ALIGN_4BYTES, ALIGN_16BYTES, ALIGN_64BYTES, ALIGN_256BYTES, ALIGN_1024BYTES, ALIGN_4096BYTES, MEM_DISCARDABLE, MEM_READ""")
    )


def test_get_section_long_name():
    """Long section names are resolved through the COFF string table"""
    coff = parse_coff("COFF/dwarf.obj")

    for name in (".debug_rnglists", ".debug_info", ".debug_str", ".debug_abbrev"):
        section = coff.get_section(name)
        assert section is not None, name
        # The raw name only holds the `/<offset>` placeholder
        assert section.name != name
        assert section.coff_string is not None
        assert section.coff_string.string == name

    assert coff.get_section(".debug_line") is None

    # The `/<offset>` placeholder is also a valid lookup key
    placeholder = coff.get_section("/18")
    assert placeholder is not None
    assert placeholder.coff_string is not None
    assert placeholder.coff_string.string == ".debug_rnglists"


@pytest.mark.private
def test_get_section_unresolved_long_name():
    """A long name whose string table entry is missing is only reachable
    through its `/<offset>` placeholder"""
    coff = parse_coff("private/COFF/coff_strtab_overflow.obj")

    assert coff.sections[0].coff_string is None
    assert coff.get_section("/18") is not None
