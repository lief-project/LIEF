import lief
from utils import get_sample

lief.logging.set_level(lief.logging.LEVEL.INFO)

def test_endianness():
    elf = lief.parse(get_sample('ELF/ELF32_x86_binary_ls.bin'))
    binary = elf.abstract
    header = binary.header

    assert header.endianness == lief.ENDIANNESS.LITTLE

    macho = lief.parse(get_sample('MachO/MachO64_x86-64_binary_id.bin'))
    binary = macho.abstract
    header = binary.header

    header.endianness == lief.ENDIANNESS.LITTLE

    pe = lief.parse(get_sample('PE/PE64_x86-64_binary_ConsoleApplication1.exe'))
    binary = pe.abstract
    header = binary.header

    header.endianness == lief.ENDIANNESS.LITTLE


def test_format():
    binary = lief.parse(get_sample('ELF/ELF32_x86_binary_ls.bin'))
    binary.abstract.format == lief.Binary.FORMATS.ELF

    binary = lief.parse(get_sample('MachO/MachO64_x86-64_binary_id.bin'))
    binary.abstract.format == lief.Binary.FORMATS.MACHO

    binary = lief.parse(get_sample('PE/PE64_x86-64_binary_ConsoleApplication1.exe'))
    binary.abstract.format == lief.Binary.FORMATS.PE

def test_pie():
    binary = lief.parse(get_sample('ELF/ELF32_ARM_binary-pie_ls.bin'))
    assert binary.abstract.is_pie

    binary = lief.parse(get_sample('MachO/MachO64_x86-64_binary_nm.bin'))
    assert binary.abstract.is_pie

    binary = lief.parse(get_sample('PE/PE32_x86_binary_cmd.exe'))
    assert binary.abstract.is_pie

    binary = lief.parse(get_sample('ELF/ELF64_x86-64_binary_ls.bin'))
    assert not binary.abstract.is_pie


def test_ctor():
    pe = lief.parse(get_sample('PE/PE32_x86_binary_winhello-mingw.exe'))
    binary = pe.abstract
    assert [f.address for f in binary.ctor_functions] == [0x4018e0, 0x401890]
    assert binary.imagebase == 0x400000

    macho = lief.parse(get_sample('MachO/MachO64_x86-64_binary_all.bin'))
    binary = macho.abstract
    assert [f.address for f in binary.ctor_functions] == [0x100000dd0]
    assert binary.imagebase == 0x100000000

    elf = lief.parse(get_sample('ELF/ELF64_x86-64_binary_gcc.bin'))
    binary = elf.abstract
    assert [f.address for f in binary.ctor_functions] == [4206768, 4206416, 4203936]
    assert binary.imagebase == 0x400000
    assert binary.offset_to_virtual_address(0xd4f38) == 0x6d4f38

    macho = lief.parse(get_sample('MachO/MachO64_x86-64_binary_sshd.bin'))
    binary = macho.abstract
    assert binary.offset_to_virtual_address(0x18f001) == 0x10019a001


def test_search():
    binary: lief.ELF.Binary = lief.parse(get_sample('ELF/ELF64_x86-64_binary_gcc.bin'))
    text = binary.get_section(".text")

    pattern = b"USH\x89\xfbH\x83\xec\x18H\x89\x14$\x89t$"
    assert text.search(pattern, 0) == 0
    assert text.search(pattern, 4) is None
    assert text.search(0x4885c0, 3) is None
    assert text.search(0x90c35f41, 4) == 22796

    rodata = binary.get_section(".rodata")
    assert rodata.search("kernel-address") == 4
    assert rodata.search("foobar") is None
    assert rodata.search_all(b"foobar") == []

def test_content():
    binary: lief.ELF.Binary = lief.parse(get_sample('ELF/ELF64_x86-64_binary_gcc.bin'))
    assert bytes(binary.abstract.get_content_from_virtual_address(0x0046d000, 0x8)) \
            == b'AWAVA\x89\xffA'

def test_function():
    binary: lief.ELF.Binary = lief.parse(get_sample('ELF/ELF64_x86-64_library_libadd.so'))
    assert binary.get_function_address("foo") == lief.lief_errors.not_found
    assert binary.get_function_address("add") == 0x6a0


def test_entropy():
    """
    from issue #976 by @PaulDance
    """
    weird_section_0 = lief.MachO.Section("weird_section_0", []).entropy
    weird_section_1 = lief.MachO.Section("weird_section_1", [1]).entropy
    assert str(weird_section_0) == "0.0"
    assert str(weird_section_1) == "0.0"

    assert weird_section_0 >= 0
    assert weird_section_1 >= 0
