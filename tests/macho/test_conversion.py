from utils import parse_macho


def test_offset2va():
    macho = parse_macho("MachO/MachO64_x86-64_binary_all.bin").at(0)
    assert macho is not None
    assert macho.offset_to_virtual_address(0x2001) == 0x100002001
    assert macho.offset_to_virtual_address(0x2001, 0x200000000) == 0x200002001

    macho = parse_macho("MachO/libadd.so").at(0)
    assert macho is not None
    assert macho.offset_to_virtual_address(0x8001) == 0xC001
    assert macho.offset_to_virtual_address(0x8001, 0x200000000) == 0x20000C001

    macho = parse_macho("MachO/do_add.bin").at(0)
    assert macho is not None
    assert macho.offset_to_virtual_address(0x8001) == 0x10000C001
    assert macho.offset_to_virtual_address(0x8001, 0x200000000) == 0x20000C001
