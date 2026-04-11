from pathlib import Path
from typing import cast

import lief
import pytest
from utils import get_sample, is_64bits_platform, parse_elf


def test_symbol_count():
    config = lief.ELF.ParserConfig()
    config.count_mtd = lief.ELF.ParserConfig.DYNSYM_COUNT.HASH
    gcc1 = parse_elf("ELF/ELF32_x86_binary_gcc.bin", config)
    config.count_mtd = lief.ELF.ParserConfig.DYNSYM_COUNT.SECTION
    gcc2 = parse_elf("ELF/ELF32_x86_binary_gcc.bin", config)
    config.count_mtd = lief.ELF.ParserConfig.DYNSYM_COUNT.RELOCATIONS
    gcc3 = parse_elf("ELF/ELF32_x86_binary_gcc.bin", config)

    assert len(gcc1.symbols) == 158
    assert len(gcc2.symbols) == 158
    assert len(gcc3.symbols) == 158


def test_issue_922():
    libcrypto_path = get_sample("ELF/libcrypto.so")
    auto = lief.ELF.parse(libcrypto_path)
    assert auto is not None
    assert len(auto.symbols) == 14757

    config = lief.ELF.ParserConfig()
    config.count_mtd = lief.ELF.ParserConfig.DYNSYM_COUNT.SECTION
    section = lief.ELF.parse(libcrypto_path, config)
    assert section is not None
    assert len(section.symbols) == 14757

    assert (
        section.virtual_address_to_offset(1000000000000)
        == lief.lief_errors.conversion_error
    )


def test_tiny():
    tiny = parse_elf("ELF/ELF32_x86_binary_tiny01.bin")
    assert len(tiny.segments) == 1
    segment = tiny.segments[0]

    assert segment.type == lief.ELF.Segment.TYPE.LOAD
    assert segment.file_offset == 0
    assert segment.virtual_address == 0x8048000
    assert segment.physical_size == 0x5A
    assert segment.virtual_size == 0x5A
    assert segment.flags == lief.ELF.Segment.FLAGS.R | lief.ELF.Segment.FLAGS.X


def test_tiny_aarch64():
    tiny = parse_elf("ELF/tiny_aarch64.elf")

    assert len(tiny.segments) == 1
    assert tiny.segments[0].virtual_address == 0x100000000
    assert tiny.segments[0].file_offset == 0
    assert tiny.segments[0].physical_size == 0x17FFFFF2
    assert len(tiny.segments[0].content) == 84
    if is_64bits_platform():
        assert lief.hash(tiny.segments[0].content) == 2547808573126369212


def test_relocations():
    bin_with_relocs = parse_elf("ELF/ELF64_x86-64_hello-with-relocs.bin")
    relocations = bin_with_relocs.relocations
    assert len(relocations) == 37
    # check relocation from .rela.text
    assert relocations[12].symbol is not None
    assert relocations[12].symbol.name == "main"
    assert relocations[12].address == 0x1064
    # check relocation from .rela.eh_frame
    assert relocations[30].has_section
    assert relocations[30].address == 0x2068


def test_corrupted_identity():
    """
    Test that we do not (only) rely on EI_DATA / EI_CLASS
    to determine the ELFCLASS and the endianness
    cf. https://tmpout.sh/2/3.html
    """
    target = parse_elf("ELF/hello_ei_data.elf")
    assert len(target.segments) == 10


def test_identity():
    target = parse_elf("ELF/ELF64_x86-64_binary_all.bin")
    target.header.identity = "foo"
    # TODO(romain)
    # target.header.identity = b"foo"
    # target.header.identity = [1, 2, 3]


def test_issue_845():
    """
    https://github.com/lief-project/LIEF/issues/845
    """
    target = parse_elf("ELF/issue_845.elf")
    assert len(target.segments) > 1
    assert len(target.segments[1].content) == 0


def test_issue_897():
    """
    Issue #897 / PR: #898
    """
    target = parse_elf("ELF/test_897.elf")
    rel1 = target.get_relocation(0x1B39)
    assert rel1 is not None
    assert rel1.symbol is not None
    assert rel1.symbol.name == "__init_array_start"
    assert rel1.symbol_table is not None
    assert rel1.symbol_table.name == ".symtab"

    rel2 = target.get_relocation(0x1B50)
    assert rel2 is not None
    assert rel2.symbol is not None
    assert rel2.symbol.name == "__init_array_end"
    assert rel2.symbol_table is not None
    assert rel2.symbol_table.name == ".symtab"


def test_issue_954():
    target = parse_elf("ELF/main.relr.elf")
    assert target.get(lief.ELF.DynamicEntry.TAG.RELA) is not None
    assert target.get(lief.ELF.DynamicEntry.TAG.RELRSZ) is not None
    assert target.get(lief.ELF.DynamicEntry.TAG.RELRENT) is not None


def test_issue_958():
    target = parse_elf("ELF/issue_958.elf")
    assert len(target.functions) == 2


def test_issue_959():
    target = parse_elf("ELF/mbedtls_selftest.elf64")
    sym_1 = cast(lief.ELF.Symbol, target.get_symbol("mbedtls_hmac_drbg_random"))
    assert sym_1 is not None
    assert sym_1.shndx > 0
    assert sym_1.section is not None
    assert sym_1.section.name == ".text"

    sym_2 = cast(lief.ELF.Symbol, target.get_symbol("stderr"))
    assert sym_2 is not None
    assert sym_2.shndx > 0
    assert sym_2.section is not None
    assert sym_2.section.name == ".bss"


def test_io():
    class Wrong:
        pass

    wrong_io = Wrong()
    assert lief.ELF.parse(wrong_io) is None  # type: ignore
    with open(get_sample("ELF/test_897.elf"), "rb") as f:
        assert lief.ELF.parse(f) is not None


def test_path_like():
    assert lief.ELF.parse(Path(get_sample("ELF/test_897.elf"))) is not None


def test_984():
    elf = parse_elf("ELF/issue_984_ilp32.o")
    assert len(elf.sections) > 0


def test_975():
    elf = parse_elf("ELF/issue_975_aarch64.o")
    for note in elf.notes:
        lief.logging.info(note)


@pytest.mark.private
def test_1058():
    elf = parse_elf("private/ELF/cn-105.elf")

    init_entry = cast(
        lief.ELF.DynamicEntryArray, elf.get(lief.ELF.DynamicEntry.TAG.INIT_ARRAY)
    )
    assert init_entry is not None
    original_init = init_entry.array
    relocated_init = elf.get_relocated_dynamic_array(
        lief.ELF.DynamicEntry.TAG.INIT_ARRAY
    )

    assert original_init == [
        0xFFFFFFFFFFFFFFFF,
        0x7AB000,
        0x7AB000,
        0x7AB000,
        0x7AB000,
        0x7AB000,
        0x7AB000,
        0x7AB000,
        0x7AB000,
        0x7AB000,
        0x7AB000,
        0x7AB000,
        0x7AB000,
        0x0,
    ]

    assert relocated_init == [
        0xFFFFFFFFFFFFFFFF,
        0x96DB10,
        0x9B9C14,
        0xE7F660,
        0xE7F70C,
        0xE7F888,
        0xE7F8E0,
        0xEBEB74,
        0xEBFC68,
        0xEC0898,
        0xEC0B98,
        0xF52DB0,
        0xF8FB20,
        0x0,
    ]

    fini_entry = cast(
        lief.ELF.DynamicEntryArray, elf.get(lief.ELF.DynamicEntry.TAG.FINI_ARRAY)
    )
    assert fini_entry is not None
    original_fini = fini_entry.array
    relocated_fini = elf.get_relocated_dynamic_array(
        lief.ELF.DynamicEntry.TAG.FINI_ARRAY
    )

    assert original_fini == [0xFFFFFFFFFFFFFFFF, 0x0]
    assert relocated_fini == [0xFFFFFFFFFFFFFFFF, 0x0]


def test_is_android():
    elf = parse_elf("ELF/ELF64_AArch64_piebinary_ndkr16.bin")
    assert elf.is_targeting_android

    elf = parse_elf("ELF/ELF64_x86-64_binary_empty-gnu-hash.bin")
    assert not elf.is_targeting_android

    elf = parse_elf("ELF/libmonochrome-armv7.so")
    assert elf.is_targeting_android


def test_ebpf_relocations():
    elf = parse_elf("ELF/hello.bpf.o")
    relocations = list(elf.relocations)

    assert len(relocations) == 9

    assert relocations[0].symbol is not None
    assert relocations[0].symbol.name == "pid_filter"
    assert relocations[0].section is not None
    assert relocations[0].section.name == ".BTF"
    assert relocations[0].address == 0x0000D4
    assert relocations[0].addend == 0
    assert relocations[0].info == 3
    assert relocations[0].purpose == lief.ELF.Relocation.PURPOSE.OBJECT
    assert relocations[0].type == lief.ELF.Relocation.TYPE.BPF_64_ABS32

    assert relocations[1].symbol is not None
    assert relocations[1].symbol.name == "LICENSE"
    assert relocations[1].section is not None
    assert relocations[1].section.name == ".BTF"
    assert relocations[1].address == 0x0000EC
    assert relocations[1].addend == 0
    assert relocations[1].info == 4
    assert relocations[1].purpose == lief.ELF.Relocation.PURPOSE.OBJECT
    assert relocations[1].type == lief.ELF.Relocation.TYPE.BPF_64_NODYLD32

    assert relocations[8].symbol is not None
    assert relocations[8].symbol.name == ""
    assert relocations[8].section is not None
    assert relocations[8].section.name == ".BTF.ext"
    assert relocations[8].address == 0x000090
    assert relocations[8].addend == 0
    assert relocations[8].info == 1
    assert relocations[8].purpose == lief.ELF.Relocation.PURPOSE.OBJECT
    assert relocations[8].type == lief.ELF.Relocation.TYPE.BPF_64_NODYLD32


def test_issue_dynamic_table():
    elf = parse_elf("ELF/issue_dynamic_table.elf")
    dyn_entries = list(elf.dynamic_entries)
    assert len(dyn_entries) == 28
    assert dyn_entries[0].name == "libselinux.so.1"  # type: ignore


def test_i64_big_endian():
    """From issue #1164"""
    elf = parse_elf("ELF/elf-HPUX-ia64-bash")
    assert elf.dynamic_entries[13].tag == lief.ELF.DynamicEntry.TAG.IA_64_VMS_IDENT


def test_i64_custom_types():
    elf = parse_elf("ELF/elf-HPUX-ia64-bash")
    assert elf.segments[11].type == lief.ELF.Segment.TYPE.HP_STACK
    assert elf.segments[11].flags == lief.ELF.Segment.FLAGS.R | lief.ELF.Segment.FLAGS.W

    elf = parse_elf("ELF/elf-Linux-Alpha-bash")
    assert elf.segments[9].type == lief.ELF.Segment.TYPE.PAX_FLAGS
    assert elf.segments[9].raw_flags == 10240


def test_issue_1177():
    elf = parse_elf("ELF/main_issue_1177.bin")
    assert len(elf.dynamic_symbols) == 5
