from textwrap import dedent

import lief
from utils import get_sample, parse_coff


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
