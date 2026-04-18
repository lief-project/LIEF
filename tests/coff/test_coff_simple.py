from textwrap import dedent
from typing import cast

import lief
from utils import get_sample, parse_coff


def test_simple_coff():
    assert lief.is_coff(get_sample("COFF/arm64_debug_cl.obj"))
    coff = parse_coff("COFF/arm64_debug_cl.obj")
    header = cast(lief.COFF.RegularHeader, coff.header)
    assert isinstance(header, lief.COFF.RegularHeader)
    assert len(str(header)) > 0
    assert header.machine == lief.PE.Header.MACHINE_TYPES.ARM64
    assert header.nb_sections == 25
    assert header.timedatestamp == 0x683DC2F9
    assert header.pointerto_symbol_table == 0x8E7F
    assert header.nb_symbols == 83
    assert header.sizeof_optionalheader == 0
    assert header.characteristics == 0

    section = coff.sections[0]
    assert (
        str(section)
        == dedent("""\
    Name:                    .drectve (2e 64 72 65 63 74 76 65)
    Virtual Size             0x0
    Virtual Address          0x0
    Size of raw data         0x91
    Pointer to raw data      0x3fc
    Range                    [0x000003fc, 0x0000048d]
    Pointer to relocations   0x0
    Pointer to line numbers  0x0
    Number of relocations    0x0
    Number of lines          0x0
    Characteristics          LNK_INFO, LNK_REMOVE, ALIGN_1BYTES, ALIGN_4BYTES, ALIGN_16BYTES, ALIGN_64BYTES, ALIGN_256BYTES, ALIGN_1024BYTES, ALIGN_4096BYTES""")
    )
    assert section.name == ".drectve"
    assert section.virtual_size == 0
    assert section.virtual_address == 0
    assert section.sizeof_raw_data == 0x91
    assert section.pointerto_raw_data == 0x3FC
    assert section.pointerto_relocation == 0
    assert section.numberof_relocations == 0
    assert section.pointerto_line_numbers == 0
    assert section.numberof_line_numbers == 0

    assert section.has_characteristic(lief.PE.Section.CHARACTERISTICS.LNK_INFO)
    assert section.has_characteristic(lief.PE.Section.CHARACTERISTICS.LNK_REMOVE)
    assert not section.has_extended_relocations

    assert len(section.relocations) == 0
    section = coff.sections[9]

    assert (
        str(section)
        == dedent("""\
    Name:                    .debug$S (2e 64 65 62 75 67 24 53)
    Virtual Size             0x0
    Virtual Address          0x0
    Size of raw data         0xf8
    Pointer to raw data      0x8a91
    Range                    [0x00008a91, 0x00008b89]
    Pointer to relocations   0x8b89
    Pointer to line numbers  0x0
    Number of relocations    0x6
    Number of lines          0x0
    Characteristics          CNT_INITIALIZED_DATA, LNK_COMDAT, ALIGN_1BYTES, ALIGN_4BYTES, ALIGN_16BYTES, ALIGN_64BYTES, ALIGN_256BYTES, ALIGN_1024BYTES, ALIGN_4096BYTES, MEM_DISCARDABLE, MEM_READ""")
    )

    assert len(section.relocations) == 6
    assert section.relocations[0].address == 0x0000002C
    assert section.relocations[0].type == lief.COFF.Relocation.TYPE.ARM64_SECREL
    assert section.relocations[0].symbol_idx == 0x1B
    _sym0 = section.relocations[0].symbol
    assert _sym0 is not None
    assert _sym0.name == "printf"

    assert section.relocations[5].address == 0x000000BC
    assert section.relocations[5].type == lief.COFF.Relocation.TYPE.ARM64_SECTION
    assert section.relocations[5].symbol_idx == 0x1B
    _sym5 = section.relocations[5].symbol
    assert _sym5 is not None
    assert _sym5.name == "printf"

    assert len(coff.symbols) == 58
    assert str(coff.symbols[0]) == dedent("""\
    Symbol {
      Name: @comp.id
      Value: 17139332
      Section index: -1
      Base type: NULL (0)
      Complex type: NULL (0)
      Storage class: STATIC (3)
      Nb auxiliary symbols: 0
    }
    """)
    assert coff.symbols[0].name == "@comp.id"
    assert coff.symbols[0].value == 17139332
    assert coff.symbols[0].section_idx == -1
    assert coff.symbols[0].complex_type == lief.COFF.Symbol.COMPLEX_TYPE.NULL
    assert coff.symbols[0].storage_class == lief.COFF.Symbol.STORAGE_CLASS.STATIC

    assert str(coff.symbols[57]) == dedent("""\
    Symbol {
      Name: .chks64
      Value: 0
      Section index: 25
      Base type: NULL (0)
      Complex type: NULL (0)
      Storage class: STATIC (3)
      Nb auxiliary symbols: 1
      AuxiliarySectionDefinition {
        Length: 0x0000c8
        Number of relocations: 0
        Number of line numbers: 0
        Checksum: 0x00000000
        Section index: 0
        Selection: NONE
        Reserved: 0
      }

    }
    """)

    assert len(coff.string_table) == 25
    assert coff.string_table[0].offset == 4
    assert coff.string_table[0].string == "$SG104573"

    assert coff.string_table[24].offset == 498
    assert coff.string_table[24].string == "_RTC_Shutdown.rtc$TMZ"

    assert len(coff.functions) == 8
    assert coff.find_function("NONE") is None
    assert coff.find_function("main") is not None

    # Coverage: Binary::to_string() (full binary print)
    output = str(coff)
    assert "Section" in output
    assert "Symbol" in output
    assert "Relocation" in output

    # Coverage: find_demangled_function (needs extended LIEF, but exercises the path)
    _ = coff.find_demangled_function("NONE")


def test_bigobj_coff():
    assert lief.is_coff(get_sample("COFF/x64_debug_cl_bigobj.obj"))
    coff = parse_coff("COFF/x64_debug_cl_bigobj.obj")
    header = cast(lief.COFF.BigObjHeader, coff.header)
    assert isinstance(header, lief.COFF.BigObjHeader)
    assert len(str(header)) > 0
    assert header.machine == lief.PE.Header.MACHINE_TYPES.AMD64
    assert header.nb_sections == 25
    assert header.timedatestamp == 0x683DC491
    assert header.pointerto_symbol_table == 0x88F0
    assert header.nb_symbols == 82
    assert header.sizeof_data == 0
    assert header.flags == 0
    assert header.metadata_size == 0
    assert header.metadata_offset == 0

    # Coverage: Binary::to_string for bigobj
    output = str(coff)
    assert "Section" in output


def test_auxiliary_file():
    coff = parse_coff("COFF/comdata_tls.obj")
    assert coff is not None

    found = False
    for sym in coff.symbols:
        for aux in sym.auxiliary_symbols:
            if isinstance(aux, lief.COFF.AuxiliaryFile):
                output = str(aux)
                assert "tls_callbacks.cpp" in output
                found = True
                break
        if found:
            break
    assert found


def test_header_setters():
    """Exercise setter methods on COFF headers to cover inline setters."""
    coff = parse_coff("COFF/arm64_debug_cl.obj")
    header = cast(lief.COFF.RegularHeader, coff.header)

    # RegularHeader setters
    header.machine = header.machine
    header.nb_sections = header.nb_sections
    header.timedatestamp = header.timedatestamp
    header.pointerto_symbol_table = header.pointerto_symbol_table
    header.nb_symbols = header.nb_symbols
    header.sizeof_optionalheader = header.sizeof_optionalheader
    header.characteristics = header.characteristics

    # BigObjHeader setters
    coff2 = parse_coff("COFF/x64_debug_cl_bigobj.obj")
    header2 = cast(lief.COFF.BigObjHeader, coff2.header)
    header2.machine = header2.machine
    header2.timedatestamp = header2.timedatestamp
    header2.sizeof_data = header2.sizeof_data
    header2.flags = header2.flags
    header2.metadata_size = header2.metadata_size
    header2.metadata_offset = header2.metadata_offset

    # Section setters
    sec = coff.sections[0]
    sec.virtual_size = sec.virtual_size
    sec.virtual_address = sec.virtual_address
    sec.sizeof_raw_data = sec.sizeof_raw_data
    sec.pointerto_raw_data = sec.pointerto_raw_data
    sec.pointerto_relocation = sec.pointerto_relocation
    sec.pointerto_line_numbers = sec.pointerto_line_numbers
    sec.numberof_relocations = sec.numberof_relocations
    sec.numberof_line_numbers = sec.numberof_line_numbers
    sec.characteristics = sec.characteristics


def test_comdat():
    coff = parse_coff("COFF/comdata_tls_msvc.obj")
    sec = coff.sections[164]
    comdat = sec.comdat_info
    assert comdat is not None
    assert (
        comdat.symbol.name
        == "$pdata$??$?0U_Exact_args_t@std@@V<lambda_1>@?1??main@@YAHHPEAPEBD@Z@$$V$0A@@?$tuple@V<lambda_1>@?1??main@@YAHHPEAPEBD@Z@@std@@QEAA@U_Exact_args_t@1@$$QEAV<lambda_1>@?1??main@@YAHHPEAPEBD@Z@@Z"
    )
    assert (
        comdat.kind == lief.COFF.AuxiliarySectionDefinition.COMDAT_SELECTION.ASSOCIATIVE
    )
