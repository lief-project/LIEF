from ctypes import c_int32, c_uint8, c_uint16, c_uint64, sizeof

import lief
from utils import parse_elf, parse_macho, parse_pe


def test_endianness():
    elf = parse_elf("ELF/ELF32_x86_binary_ls.bin")
    binary = elf.abstract
    header = binary.header

    assert header.endianness == lief.Header.ENDIANNESS.LITTLE

    macho = parse_macho("MachO/MachO64_x86-64_binary_id.bin").at(0)
    assert macho is not None
    binary = macho.abstract
    header = binary.header

    assert header.endianness == lief.Header.ENDIANNESS.LITTLE

    pe = parse_pe("PE/PE64_x86-64_binary_ConsoleApplication1.exe")
    binary = pe.abstract
    header = binary.header

    assert pe.get_int_from_virtual_address(0x140001004, sizeof(c_uint8)) == 0x48
    assert pe.get_int_from_virtual_address(0x140002CC8, sizeof(c_uint16)) == 0x552
    assert pe.get_int_from_virtual_address(0x1400040FC, sizeof(c_int32)) == 0x1878
    assert (
        pe.get_int_from_virtual_address(0x140001AFC, sizeof(c_uint64))
        == 0x8B485510245C8948
    )
    assert pe.get_int_from_virtual_address(0x140001AFC, 3443) is None
    assert pe.get_int_from_virtual_address(0x1840001AFC, 1) is None

    assert header.endianness == lief.Header.ENDIANNESS.LITTLE


def test_format():
    binary = parse_elf("ELF/ELF32_x86_binary_ls.bin")
    assert binary.abstract.format == lief.Binary.FORMATS.ELF

    binary = parse_macho("MachO/MachO64_x86-64_binary_id.bin").at(0)
    assert binary is not None
    assert binary.abstract.format == lief.Binary.FORMATS.MACHO

    binary = parse_pe("PE/PE64_x86-64_binary_ConsoleApplication1.exe")
    assert binary.abstract.format == lief.Binary.FORMATS.PE


def test_pie():
    binary = parse_elf("ELF/ELF32_ARM_binary-pie_ls.bin")
    assert binary.abstract.is_pie

    binary = parse_macho("MachO/MachO64_x86-64_binary_nm.bin").at(0)
    assert binary is not None
    assert binary.abstract.is_pie

    binary = parse_pe("PE/PE32_x86_binary_cmd.exe")
    assert binary.abstract.is_pie

    binary = parse_elf("ELF/ELF64_x86-64_binary_ls.bin")
    assert not binary.abstract.is_pie


def test_ctor():
    pe = parse_pe("PE/PE32_x86_binary_winhello-mingw.exe")
    binary = pe.abstract
    assert [f.address for f in binary.ctor_functions] == [0x4018E0, 0x401890]
    assert binary.imagebase == 0x400000

    macho = parse_macho("MachO/MachO64_x86-64_binary_all.bin").at(0)
    assert macho is not None
    binary = macho.abstract
    assert [f.address for f in binary.ctor_functions] == [0x100000DD0]
    assert binary.imagebase == 0x100000000

    elf = parse_elf("ELF/ELF64_x86-64_binary_gcc.bin")
    binary = elf.abstract
    assert [f.address for f in binary.ctor_functions] == [4206768, 4206416, 4203936]
    assert binary.imagebase == 0x400000
    assert binary.offset_to_virtual_address(0xD4F38) == 0x6D4F38

    macho = parse_macho("MachO/MachO64_x86-64_binary_sshd.bin").at(0)
    assert macho is not None
    binary = macho.abstract
    assert binary.offset_to_virtual_address(0x18F001) == 0x10019A001


def test_search():
    binary = parse_elf("ELF/ELF64_x86-64_binary_gcc.bin")
    text = binary.get_section(".text")
    assert text is not None

    pattern = b"USH\x89\xfbH\x83\xec\x18H\x89\x14$\x89t$"
    assert text.search(pattern, 0) == 0
    assert text.search(pattern, 4) is None
    assert text.search(0x4885C0, 3) is None
    assert text.search(0x90C35F41, 4) == 22796

    rodata = binary.get_section(".rodata")
    assert rodata is not None
    assert rodata.search("kernel-address") == 4
    assert rodata.search("foobar") is None
    assert rodata.search_all(b"foobar") == []  # type: ignore


def test_content():
    binary: lief.ELF.Binary = parse_elf("ELF/ELF64_x86-64_binary_gcc.bin")
    assert (
        bytes(binary.abstract.get_content_from_virtual_address(0x0046D000, 0x8))
        == b"AWAVA\x89\xffA"
    )


def test_function():
    binary: lief.ELF.Binary = parse_elf("ELF/ELF64_x86-64_library_libadd.so")
    assert binary.get_function_address("foo") == lief.lief_errors.not_found
    assert binary.get_function_address("add") == 0x6A0

    binary: lief.ELF.Binary = parse_elf("ELF/libip4tc.so.2.0.0")
    assert binary.get_function_address("iptc_commit") == 0x3070


def test_entropy():
    """
    from issue #976 by @PaulDance
    """
    _sec_0 = lief.MachO.Section.create("weird_section_0", [])
    assert _sec_0 is not None
    weird_section_0 = _sec_0.entropy
    _sec_1 = lief.MachO.Section.create("weird_section_1", [1])
    assert _sec_1 is not None
    weird_section_1 = _sec_1.entropy
    assert str(weird_section_0) == "0.0"
    assert str(weird_section_1) == "0.0"

    assert weird_section_0 >= 0
    assert weird_section_1 >= 0


def test_issue_1217():
    elf = parse_elf("ELF/bitcoin_ppc_be")
    assert elf.abstract.header.architecture == lief.Header.ARCHITECTURES.PPC64


def test_pagesize():
    assert parse_elf("ELF/ELF64_x86-64_library_libadd.so").page_size == 0x1000
    assert (
        parse_pe("PE/win11_arm64x_api-ms-win-security-base-l1-1-0.dll").page_size
        == 0x1000
    )
    _macho_ps = parse_macho("MachO/MachO64_AArch64_weak-sym-fc.bin").at(0)
    assert _macho_ps is not None
    assert _macho_ps.page_size == 0x4000

    config = lief.ELF.ParserConfig()
    config.page_size = 0xDEADC0DE

    assert parse_elf("ELF/bitcoin_ppc_be", config).page_size == config.page_size
