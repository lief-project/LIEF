import lief
import pytest
from utils import get_sample
from pathlib import Path
from textwrap import dedent

def test_simple_coff():
    assert lief.is_coff(get_sample("COFF/arm64_debug_cl.obj"))
    coff = lief.COFF.parse(get_sample("COFF/arm64_debug_cl.obj"))
    header: lief.COFF.RegularHeader = coff.header
    assert isinstance(header, lief.COFF.RegularHeader)
    assert len(str(header)) > 0
    assert header.machine == lief.PE.Header.MACHINE_TYPES.ARM64
    assert header.nb_sections == 25
    assert header.timedatestamp == 0x683dc2f9
    assert header.pointerto_symbol_table == 0x8e7f
    assert header.nb_symbols == 83
    assert header.sizeof_optionalheader == 0
    assert header.characteristics == 0

    section = coff.sections[0]
    assert str(section) == dedent("""\
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
    assert section.name == '.drectve'
    assert section.virtual_size == 0
    assert section.virtual_address == 0
    assert section.sizeof_raw_data == 0x91
    assert section.pointerto_raw_data == 0x3fc
    assert section.pointerto_relocation == 0
    assert section.numberof_relocations == 0
    assert section.pointerto_line_numbers == 0
    assert section.numberof_line_numbers == 0

    assert section.has_characteristic(lief.PE.Section.CHARACTERISTICS.LNK_INFO)
    assert section.has_characteristic(lief.PE.Section.CHARACTERISTICS.LNK_REMOVE)
    assert not section.has_extended_relocations

    assert len(section.relocations) == 0
    section = coff.sections[9]

    assert str(section) == dedent("""\
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

    assert len(section.relocations) == 6
    assert section.relocations[0].address == 0x0000002c
    assert section.relocations[0].type == lief.COFF.Relocation.TYPE.ARM64_SECREL
    assert section.relocations[0].symbol_idx == 0x1B
    assert section.relocations[0].symbol.name == "printf"

    assert section.relocations[5].address == 0x000000bc
    assert section.relocations[5].type == lief.COFF.Relocation.TYPE.ARM64_SECTION
    assert section.relocations[5].symbol_idx == 0x1B
    assert section.relocations[5].symbol.name == "printf"

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

def test_bigobj_coff():
    assert lief.is_coff(get_sample("COFF/x64_debug_cl_bigobj.obj"))
    coff = lief.COFF.parse(get_sample("COFF/x64_debug_cl_bigobj.obj"))
    header: lief.COFF.BigObjHeader = coff.header
    assert isinstance(header, lief.COFF.BigObjHeader)
    assert len(str(header)) > 0
    assert header.machine == lief.PE.Header.MACHINE_TYPES.AMD64
    assert header.nb_sections == 25
    assert header.timedatestamp == 0x683dc491
    assert header.pointerto_symbol_table == 0x88f0
    assert header.nb_symbols == 82
    assert header.sizeof_data == 0
    assert header.flags == 0
    assert header.metadata_size == 0
    assert header.metadata_offset == 0

def test_comdat():
    coff = lief.COFF.parse(get_sample("COFF/comdata_tls_msvc.obj"))
    sec = coff.sections[164]
    assert sec.comdat_info.symbol.name == '$pdata$??$?0U_Exact_args_t@std@@V<lambda_1>@?1??main@@YAHHPEAPEBD@Z@$$V$0A@@?$tuple@V<lambda_1>@?1??main@@YAHHPEAPEBD@Z@@std@@QEAA@U_Exact_args_t@1@$$QEAV<lambda_1>@?1??main@@YAHHPEAPEBD@Z@@Z'
    assert sec.comdat_info.kind == lief.COFF.AuxiliarySectionDefinition.COMDAT_SELECTION.ASSOCIATIVE
