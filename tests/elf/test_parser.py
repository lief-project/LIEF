import lief
from utils import get_sample, is_64bits_platform

def test_symbol_count():
    config = lief.ELF.ParserConfig()
    config.count_mtd = lief.ELF.DYNSYM_COUNT_METHODS.HASH
    gcc1 = lief.ELF.parse(get_sample('ELF/ELF32_x86_binary_gcc.bin'), config)
    config.count_mtd = lief.ELF.DYNSYM_COUNT_METHODS.SECTION
    gcc2 = lief.ELF.parse(get_sample('ELF/ELF32_x86_binary_gcc.bin'), config)
    config.count_mtd = lief.ELF.DYNSYM_COUNT_METHODS.RELOCATIONS
    gcc3 = lief.ELF.parse(get_sample('ELF/ELF32_x86_binary_gcc.bin'), config)

    assert len(gcc1.symbols) == 158
    assert len(gcc2.symbols) == 158
    assert len(gcc3.symbols) == 158

def test_issue_922():
    libcrypto_path = get_sample('ELF/libcrypto.so')
    auto = lief.ELF.parse(libcrypto_path)
    assert len(auto.symbols) == 14757

    config = lief.ELF.ParserConfig()
    config.count_mtd = lief.ELF.DYNSYM_COUNT_METHODS.SECTION
    section = lief.ELF.parse(libcrypto_path, config)
    assert len(section.symbols) == 14757

    assert section.virtual_address_to_offset(1000000000000) == lief.lief_errors.conversion_error

def test_tiny():
    tiny = lief.parse(get_sample('ELF/ELF32_x86_binary_tiny01.bin'))
    assert len(tiny.segments) == 1
    segment = tiny.segments[0]

    assert segment.type == lief.ELF.SEGMENT_TYPES.LOAD
    assert segment.file_offset == 0
    assert segment.virtual_address == 0x8048000
    assert segment.physical_size == 0x5a
    assert segment.virtual_size == 0x5a
    assert int(segment.flags) == lief.ELF.SEGMENT_FLAGS.R | lief.ELF.SEGMENT_FLAGS.X

def test_tiny_aarch64():
    tiny = lief.parse(get_sample('ELF/tiny_aarch64.elf'))

    assert len(tiny.segments) == 1
    assert tiny.segments[0].virtual_address == 0x100000000
    assert tiny.segments[0].file_offset == 0
    assert tiny.segments[0].physical_size == 0x17fffff2
    assert len(tiny.segments[0].content) == 84
    if is_64bits_platform():
        assert lief.hash(tiny.segments[0].content) == 2547808573126369212

def test_relocations():
    bin_with_relocs = lief.parse(get_sample('ELF/ELF64_x86-64_hello-with-relocs.bin'))
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
    target = lief.parse(get_sample('ELF/hello_ei_data.elf'))
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
    target = lief.parse(get_sample('ELF/issue_845.elf'))
    assert len(target.segments) > 1
    assert len(target.segments[1].content) == 0

def test_issue_897():
    """
    Issue #897 / PR: #898
    """
    target = lief.parse(get_sample('ELF/test_897.elf'))
    rel1 = target.get_relocation(0x1b39)
    assert rel1.symbol.name == "__init_array_start"
    assert rel1.symbol_table.name == ".symtab"

    rel2 = target.get_relocation(0x1b50)
    assert rel2.symbol.name == "__init_array_end"
    assert rel2.symbol_table.name == ".symtab"


def test_io():
    class Wrong:
        pass
    wrong_io = Wrong()
    assert lief.ELF.parse(wrong_io) is None
    with open(get_sample('ELF/test_897.elf'), "rb") as f:
        assert lief.ELF.parse(f) is not None
