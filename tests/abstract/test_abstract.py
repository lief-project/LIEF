
import lief
from utils import get_sample

lief.logging.set_level(lief.logging.LOGGING_LEVEL.INFO)

def test_endianness():
    binary = lief.parse(get_sample('ELF/ELF32_x86_binary_ls.bin')).abstract
    header = binary.header

    assert header.endianness == lief.ENDIANNESS.LITTLE

    binary = lief.parse(get_sample('MachO/MachO64_x86-64_binary_id.bin')).abstract
    header = binary.header

    header.endianness == lief.ENDIANNESS.LITTLE

    binary = lief.parse(get_sample('PE/PE64_x86-64_binary_ConsoleApplication1.exe')).abstract
    header = binary.header

    header.endianness == lief.ENDIANNESS.LITTLE


def test_format():
    binary = lief.parse(get_sample('ELF/ELF32_x86_binary_ls.bin')).abstract
    binary.format == lief.EXE_FORMATS.ELF

    binary = lief.parse(get_sample('MachO/MachO64_x86-64_binary_id.bin')).abstract
    binary.format == lief.EXE_FORMATS.MACHO

    binary = lief.parse(get_sample('PE/PE64_x86-64_binary_ConsoleApplication1.exe')).abstract
    binary.format == lief.EXE_FORMATS.PE

def test_pie():
    binary = lief.parse(get_sample('ELF/ELF32_ARM_binary-pie_ls.bin')).abstract
    assert binary.is_pie

    binary = lief.parse(get_sample('MachO/MachO64_x86-64_binary_nm.bin')).abstract
    assert binary.is_pie

    binary = lief.parse(get_sample('PE/PE32_x86_binary_cmd.exe')).abstract
    assert binary.is_pie

    binary = lief.parse(get_sample('ELF/ELF64_x86-64_binary_ls.bin')).abstract
    assert not binary.is_pie


def test_ctor():
    binary = lief.parse(get_sample('PE/PE32_x86_binary_winhello-mingw.exe')).abstract
    assert [f.address for f in binary.ctor_functions] == [0x4018e0, 0x401890]
    assert binary.imagebase == 0x400000

    binary = lief.parse(get_sample('MachO/MachO64_x86-64_binary_all.bin')).abstract
    assert [f.address for f in binary.ctor_functions] == [0x100000dd0]
    assert binary.imagebase == 0x100000000

    binary = lief.parse(get_sample('ELF/ELF64_x86-64_binary_gcc.bin')).abstract
    assert [f.address for f in binary.ctor_functions] == [4206768, 4206416, 4203936]
    assert binary.imagebase == 0x400000
    assert binary.offset_to_virtual_address(0xd4f38) == 0x6d4f38

    binary = lief.parse(get_sample('MachO/MachO64_x86-64_binary_sshd.bin')).abstract
    assert binary.offset_to_virtual_address(0x18f001) == 0x10019a001
