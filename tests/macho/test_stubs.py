import lief
import pytest
from utils import get_sample, has_private_samples
#lief.logging.set_level(lief.logging.LEVEL.DEBUG)

def test_simple():
    macho = lief.MachO.parse(get_sample("MachO/liblog_srp.dylib")).at(0)
    stubs = macho.symbol_stubs

    assert len([s for s in macho.sections if s.type == lief.MachO.Section.TYPE.SYMBOL_STUBS]) == 1
    assert len(stubs) == 25

    assert stubs[0].address == 0x236a3c1bc
    assert stubs[1].address == 0x236a3c1cc
    assert stubs[24].address == 0x236A3C33C
    assert str(stubs[2])

def test_IOKit():
    macho = lief.MachO.parse(get_sample("MachO/IOKit")).at(0)
    assert macho.header.cpu_subtype == 6 # CPU_SUBTYPE_ARM_V6
    assert macho.header.cpu_type == lief.MachO.Header.CPU_TYPE.ARM
    stubs = macho.symbol_stubs

    sections = [s.name for s in macho.sections if s.type == lief.MachO.Section.TYPE.SYMBOL_STUBS]
    assert len(sections) == 2

    assert sections[0] == "__picsymbolstub1"
    assert sections[1] == "__picsymbolstub4"

    assert len(stubs) == 334

    assert stubs[0].address == 0x30a204dc
    assert stubs[333].address == 0x30a219ac

def test_arm32():
    macho = lief.MachO.parse(get_sample("MachO/ios1-expr.bin")).at(0)
    assert macho.header.cpu_type == lief.MachO.Header.CPU_TYPE.ARM
    assert macho.header.cpu_subtype == 6 # CPU_SUBTYPE_ARM_V6
    stubs = macho.symbol_stubs

    sections = [s.name for s in macho.sections if s.type == lief.MachO.Section.TYPE.SYMBOL_STUBS]
    assert len(sections) == 4

    assert sections[0] == "__picsymbolstub1"
    assert sections[1] == "__symbol_stub1"
    assert sections[2] == "__picsymbolstub4"
    assert sections[3] == "__symbol_stub4"

    assert len(stubs) == 23

    assert stubs[0].address == 0x2ee0
    assert stubs[1].address == 0x2ef0
    assert stubs[2].address == 0x2f00
    assert stubs[3].address == 0x2f10
    assert stubs[4].address == 0x2f1c
    assert stubs[5].address == 0x2f28
    assert stubs[6].address == 0x2f34
    assert stubs[7].address == 0x2f40
    assert stubs[8].address == 0x2f4c
    assert stubs[9].address == 0x2f58
    assert stubs[10].address == 0x2f64
    assert stubs[11].address == 0x2f70
    assert stubs[12].address == 0x2f7c
    assert stubs[13].address == 0x2f88
    assert stubs[14].address == 0x2f94
    assert stubs[15].address == 0x2fa0
    assert stubs[16].address == 0x2fac
    assert stubs[17].address == 0x2fb8
    assert stubs[18].address == 0x2fc4
    assert stubs[19].address == 0x2fd0
    assert stubs[20].address == 0x2fdc
    assert stubs[21].address == 0x2fe8
    assert stubs[22].address == 0x2ff4

@pytest.mark.skipif(not has_private_samples(), reason="needs private samples")
def test_empty_section():
    macho = lief.MachO.parse(get_sample("private/DWARF/libLIEF.dylib")).at(0)

    stubs = macho.symbol_stubs

    sections = [s for s in macho.sections if s.type == lief.MachO.Section.TYPE.SYMBOL_STUBS]
    assert len(sections) == 1

    assert sections[0].name == "__stubs"
    assert sections[0].size > 0
    assert len(sections[0].content) == 0

    assert len(stubs) == 0
    assert len(list(stubs)) == 0

def test_stub_resolution():
    raw_stub = [
        # Address: 0x3c47b08
        0x10, 0x79, 0x00, 0xF0, # ADRP  X16, #0x4B6A000
        0x10, 0x9E, 0x43, 0xF9, # LDR   X16, [X16,#0x738]
        0x00, 0x02, 0x1F, 0xD6, # BR    X16
    ]
    target = lief.MachO.Stub.target_info_t(lief.MachO.Header.CPU_TYPE.ARM64, 0)
    stub = lief.MachO.Stub(target, 0x3c47b08, raw_stub)
    assert stub.target == 0x4b6a738 if lief.__extended__ else lief.lief_errors.require_extended_version

    raw_stub = [
        # Address: 0x1804e4284
        0x50, 0x2B, 0x23, 0x90, # ADRP  X16, #0x1C6A4C000
        0x10, 0x22, 0x13, 0x91, # ADD   X16, X16, #0x4C8
        0x00, 0x02, 0x1F, 0xD6, # BR    X16
    ]
    target = lief.MachO.Stub.target_info_t(lief.MachO.Header.CPU_TYPE.ARM64, 0)
    stub = lief.MachO.Stub(target, 0x1804e4284, raw_stub)
    assert stub.target == 0x1c6a4c4c8 if lief.__extended__ else lief.lief_errors.require_extended_version

    raw_stub = [
        # Address: 0x2018310
        0x91, 0x08, 0x00, 0x90, # ADRP x17, #1114112
        0x31, 0x02, 0x00, 0x91, # ADD  X17, X17, #0
        0x30, 0x02, 0x40, 0xf9, # LDR  X16, [X17]
        0x11, 0x0a, 0x1f, 0xd7, # BRAA x16, x17
    ]
    target = lief.MachO.Stub.target_info_t(lief.MachO.Header.CPU_TYPE.ARM64, 2)
    stub = lief.MachO.Stub(target, 0x2018310, raw_stub)
    assert stub.target == 0x2128000 if lief.__extended__ else lief.lief_errors.require_extended_version

    raw_stub = [
        # Address: 0x100175f2c
        0x1f, 0x20, 0x03, 0xd5, # NOP
        0xd0, 0x13, 0x3b, 0x58, # LDR X16, #483960
        0x00, 0x02, 0x1F, 0xD6, # BR  X16
    ]
    target = lief.MachO.Stub.target_info_t(lief.MachO.Header.CPU_TYPE.ARM64, 2)
    stub = lief.MachO.Stub(target, 0x100175f2c, raw_stub)
    assert stub.target == 0x1001ec1a8 if lief.__extended__ else lief.lief_errors.require_extended_version

    raw_stub = [
        # Address: 0x100003b14
        0xff, 0x25, 0xe6, 0x44, 0x00, 0x00, # jmp qword ptr [rip + 17638]
    ]
    target = lief.MachO.Stub.target_info_t(lief.MachO.Header.CPU_TYPE.X86_64, 0)
    stub = lief.MachO.Stub(target, 0x100003b14, raw_stub)
    assert stub.target == 0x100008000 if lief.__extended__ else lief.lief_errors.require_extended_version


