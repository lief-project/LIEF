import lief
import pytest
from utils import get_sample, is_64bits_platform, glibc_version, has_private_samples
from pathlib import Path

def test_symbol_count():
    config = lief.ELF.ParserConfig()
    config.count_mtd = lief.ELF.ParserConfig.DYNSYM_COUNT.HASH
    gcc1 = lief.ELF.parse(get_sample('ELF/ELF32_x86_binary_gcc.bin'), config)
    config.count_mtd = lief.ELF.ParserConfig.DYNSYM_COUNT.SECTION
    gcc2 = lief.ELF.parse(get_sample('ELF/ELF32_x86_binary_gcc.bin'), config)
    config.count_mtd = lief.ELF.ParserConfig.DYNSYM_COUNT.RELOCATIONS
    gcc3 = lief.ELF.parse(get_sample('ELF/ELF32_x86_binary_gcc.bin'), config)

    assert len(gcc1.symbols) == 158
    assert len(gcc2.symbols) == 158
    assert len(gcc3.symbols) == 158

def test_issue_922():
    libcrypto_path = get_sample('ELF/libcrypto.so')
    auto = lief.ELF.parse(libcrypto_path)
    assert len(auto.symbols) == 14757

    config = lief.ELF.ParserConfig()
    config.count_mtd = lief.ELF.ParserConfig.DYNSYM_COUNT.SECTION
    section = lief.ELF.parse(libcrypto_path, config)
    assert len(section.symbols) == 14757

    assert section.virtual_address_to_offset(1000000000000) == lief.lief_errors.conversion_error

def test_tiny():
    tiny = lief.ELF.parse(get_sample('ELF/ELF32_x86_binary_tiny01.bin'))
    assert len(tiny.segments) == 1
    segment = tiny.segments[0]

    assert segment.type == lief.ELF.Segment.TYPE.LOAD
    assert segment.file_offset == 0
    assert segment.virtual_address == 0x8048000
    assert segment.physical_size == 0x5a
    assert segment.virtual_size == 0x5a
    assert int(segment.flags) == lief.ELF.Segment.FLAGS.R | lief.ELF.Segment.FLAGS.X

def test_tiny_aarch64():
    tiny = lief.ELF.parse(get_sample('ELF/tiny_aarch64.elf'))

    assert len(tiny.segments) == 1
    assert tiny.segments[0].virtual_address == 0x100000000
    assert tiny.segments[0].file_offset == 0
    assert tiny.segments[0].physical_size == 0x17fffff2
    assert len(tiny.segments[0].content) == 84
    if is_64bits_platform():
        assert lief.hash(tiny.segments[0].content) == 2547808573126369212

def test_relocations():
    bin_with_relocs = lief.ELF.parse(get_sample('ELF/ELF64_x86-64_hello-with-relocs.bin'))
    relocations = bin_with_relocs.relocations
    assert len(relocations) == 37
    # check relocation from .rela.text
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
    target = lief.ELF.parse(get_sample('ELF/hello_ei_data.elf'))
    assert len(target.segments) == 10


def test_identity():
    target = lief.ELF.parse(get_sample('ELF/ELF64_x86-64_binary_all.bin'))
    target.header.identity = "foo"
    # TODO(romain)
    #target.header.identity = b"foo"
    #target.header.identity = [1, 2, 3]

def test_issue_845():
    """
    https://github.com/lief-project/LIEF/issues/845
    """
    target = lief.ELF.parse(get_sample('ELF/issue_845.elf'))
    assert len(target.segments) > 1
    assert len(target.segments[1].content) == 0

def test_issue_897():
    """
    Issue #897 / PR: #898
    """
    target = lief.ELF.parse(get_sample('ELF/test_897.elf'))
    rel1 = target.get_relocation(0x1b39)
    assert rel1.symbol.name == "__init_array_start"
    assert rel1.symbol_table.name == ".symtab"

    rel2 = target.get_relocation(0x1b50)
    assert rel2.symbol.name == "__init_array_end"
    assert rel2.symbol_table.name == ".symtab"

def test_issue_954():
    target = lief.ELF.parse(get_sample('ELF/main.relr.elf'))
    assert target.get(lief.ELF.DynamicEntry.TAG.RELA) is not None
    assert target.get(lief.ELF.DynamicEntry.TAG.RELRSZ) is not None
    assert target.get(lief.ELF.DynamicEntry.TAG.RELRENT) is not None

def test_issue_958():
    target = lief.ELF.parse(get_sample('ELF/issue_958.elf'))
    assert len(target.functions) == 2

def test_issue_959():
    target = lief.ELF.parse(get_sample('ELF/mbedtls_selftest.elf64'))
    sym_1: lief.ELF.Symbol = target.get_symbol("mbedtls_hmac_drbg_random")
    assert sym_1.shndx > 0
    assert sym_1.section is not None
    assert sym_1.section.name == ".text"

    sym_2: lief.ELF.Symbol = target.get_symbol("stderr")
    assert sym_2.shndx > 0
    assert sym_2.section is not None
    assert sym_2.section.name == ".bss"

def test_io():
    class Wrong:
        pass
    wrong_io = Wrong()
    assert lief.ELF.parse(wrong_io) is None # type: ignore
    with open(get_sample('ELF/test_897.elf'), "rb") as f:
        assert lief.ELF.parse(f) is not None

def test_path_like():
    assert lief.ELF.parse(Path(get_sample('ELF/test_897.elf'))) is not None

def test_984():
    elf = lief.ELF.parse(get_sample('ELF/issue_984_ilp32.o'))
    assert len(elf.sections) > 0

def test_975():
    elf = lief.ELF.parse(get_sample('ELF/issue_975_aarch64.o'))
    for note in elf.notes:
        print(note)

@pytest.mark.skipif(not has_private_samples(), reason="needs private samples")
def test_1058():
    elf = lief.ELF.parse(get_sample("private/ELF/cn-105.elf"))

    original_init = elf.get(lief.ELF.DynamicEntry.TAG.INIT_ARRAY).array
    relocated_init = elf.get_relocated_dynamic_array(lief.ELF.DynamicEntry.TAG.INIT_ARRAY)

    assert original_init == [
        0xffffffffffffffff,
        0x7ab000, 0x7ab000, 0x7ab000, 0x7ab000, 0x7ab000, 0x7ab000, 0x7ab000,
        0x7ab000, 0x7ab000, 0x7ab000, 0x7ab000, 0x7ab000, 0x0
    ]

    assert relocated_init == [
        0xffffffffffffffff,
        0x96db10, 0x9b9c14, 0xe7f660, 0xe7f70c, 0xe7f888, 0xe7f8e0, 0xebeb74,
        0xebfc68, 0xec0898, 0xec0b98, 0xf52db0, 0xf8fb20, 0x0
    ]

    original_fini = elf.get(lief.ELF.DynamicEntry.TAG.FINI_ARRAY).array
    relocated_fini = elf.get_relocated_dynamic_array(lief.ELF.DynamicEntry.TAG.FINI_ARRAY)

    assert original_fini == [0xffffffffffffffff, 0x0]
    assert relocated_fini == [0xffffffffffffffff, 0x0]
