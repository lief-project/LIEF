import lief

from utils import get_sample

def test_offset2va():
    macho = lief.MachO.parse(get_sample("MachO/MachO64_x86-64_binary_all.bin")).at(0)
    assert macho.offset_to_virtual_address(0x2001) == 0x100002001
    assert macho.offset_to_virtual_address(0x2001, 0x200000000) == 0x200002001

    macho = lief.MachO.parse(get_sample("MachO/libadd.so")).at(0)
    assert macho.offset_to_virtual_address(0x8001) == 0xc001
    assert macho.offset_to_virtual_address(0x8001, 0x200000000) == 0x20000c001

    macho = lief.MachO.parse(get_sample("MachO/do_add.bin")).at(0)
    assert macho.offset_to_virtual_address(0x8001) == 0x10000c001
    assert macho.offset_to_virtual_address(0x8001, 0x200000000) == 0x20000c001
