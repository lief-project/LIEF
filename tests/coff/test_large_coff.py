from textwrap import dedent

import pytest
from utils import parse_coff


@pytest.mark.private
def test_relocation_overflow():
    coff = parse_coff("private/COFF/relocations_overflow.obj")

    section = coff.sections[3]

    assert section.has_extended_relocations
    assert section.numberof_relocations == 0xFFFF
    assert len(section.relocations) == 131077
    assert section.relocations[0].address == 131077
    assert (
        str(section.relocations[131076])
        == dedent("""\
    0x000f0022                AMD64_REL32 0x00000016 symbol=?foo@@YAHHH@Z section=.text""")
    )


@pytest.mark.private
def test_sections_overflow():
    coff = parse_coff("private/COFF/big_coff.cpp.obj")
    assert len(coff.sections) == 65541
    assert coff.sections[0].symbols[1].auxiliary_symbols[0].section_idx == 65537  # type: ignore
