import lief
from utils import get_sample, is_64bits_platform

def test_symbol_count():
    gcc1 = lief.ELF.parse(get_sample('ELF/ELF32_x86_binary_gcc.bin'), lief.ELF.DYNSYM_COUNT_METHODS.HASH)
    gcc2 = lief.ELF.parse(get_sample('ELF/ELF32_x86_binary_gcc.bin'), lief.ELF.DYNSYM_COUNT_METHODS.SECTION)
    gcc3 = lief.ELF.parse(get_sample('ELF/ELF32_x86_binary_gcc.bin'), lief.ELF.DYNSYM_COUNT_METHODS.RELOCATIONS)

    assert len(gcc1.symbols) == 158
    assert len(gcc2.symbols) == 158
    assert len(gcc3.symbols) == 158

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

def test_issue_845():
    """
    https://github.com/lief-project/LIEF/issues/845
    """
    target = lief.parse(get_sample('ELF/issue_845.elf'))
    assert len(target.segments) > 1
    assert len(target.segments[1].content) == 0
