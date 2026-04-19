import lief
import pytest
from utils import parse_macho


def test_simple():
    macho = parse_macho("MachO/liblog_srp.dylib").at(0)
    assert macho is not None
    stubs = macho.symbol_stubs

    assert (
        len(
            [s for s in macho.sections if s.type == lief.MachO.Section.TYPE.SYMBOL_STUBS] # fmt: off
        ) == 1
    )  # fmt: off
    assert len(stubs) == 25

    assert stubs[0].address == 0x236A3C1BC
    assert stubs[1].address == 0x236A3C1CC
    assert stubs[24].address == 0x236A3C33C
    assert str(stubs[2])


def test_IOKit():
    macho = parse_macho("MachO/IOKit").at(0)
    assert macho is not None
    assert macho.header.cpu_subtype == 6  # CPU_SUBTYPE_ARM_V6
    assert macho.header.cpu_type == lief.MachO.Header.CPU_TYPE.ARM
    stubs = macho.symbol_stubs

    sections = [
        s.name for s in macho.sections if s.type == lief.MachO.Section.TYPE.SYMBOL_STUBS
    ]
    assert len(sections) == 2

    assert sections[0] == "__picsymbolstub1"
    assert sections[1] == "__picsymbolstub4"

    assert len(stubs) == 334

    assert stubs[0].address == 0x30A204DC
    assert stubs[333].address == 0x30A219AC


def test_arm32():
    macho = parse_macho("MachO/ios1-expr.bin").at(0)
    assert macho is not None
    assert macho.header.cpu_type == lief.MachO.Header.CPU_TYPE.ARM
    assert macho.header.cpu_subtype == 6  # CPU_SUBTYPE_ARM_V6
    stubs = macho.symbol_stubs

    sections = [
        s.name for s in macho.sections if s.type == lief.MachO.Section.TYPE.SYMBOL_STUBS
    ]
    assert len(sections) == 4

    assert sections[0] == "__picsymbolstub1"
    assert sections[1] == "__symbol_stub1"
    assert sections[2] == "__picsymbolstub4"
    assert sections[3] == "__symbol_stub4"

    assert len(stubs) == 23

    assert stubs[0].address == 0x2EE0
    assert stubs[1].address == 0x2EF0
    assert stubs[2].address == 0x2F00
    assert stubs[3].address == 0x2F10
    assert stubs[4].address == 0x2F1C
    assert stubs[5].address == 0x2F28
    assert stubs[6].address == 0x2F34
    assert stubs[7].address == 0x2F40
    assert stubs[8].address == 0x2F4C
    assert stubs[9].address == 0x2F58
    assert stubs[10].address == 0x2F64
    assert stubs[11].address == 0x2F70
    assert stubs[12].address == 0x2F7C
    assert stubs[13].address == 0x2F88
    assert stubs[14].address == 0x2F94
    assert stubs[15].address == 0x2FA0
    assert stubs[16].address == 0x2FAC
    assert stubs[17].address == 0x2FB8
    assert stubs[18].address == 0x2FC4
    assert stubs[19].address == 0x2FD0
    assert stubs[20].address == 0x2FDC
    assert stubs[21].address == 0x2FE8
    assert stubs[22].address == 0x2FF4


@pytest.mark.private
def test_empty_section():
    macho = parse_macho("private/DWARF/libLIEF.dylib").at(0)
    assert macho is not None

    stubs = macho.symbol_stubs

    sections = [
        s for s in macho.sections if s.type == lief.MachO.Section.TYPE.SYMBOL_STUBS
    ]
    assert len(sections) == 1

    assert sections[0].name == "__stubs"
    assert sections[0].size > 0
    assert len(sections[0].content) == 0

    assert len(stubs) == 0
    assert len(list(stubs)) == 0


def test_stub_resolution():
    raw_stub = [
        # Address: 0x3c47b08
        0x10, 0x79, 0x00, 0xF0,  # ADRP  X16, #0x4B6A000
        0x10, 0x9E, 0x43, 0xF9,  # LDR   X16, [X16,#0x738]
        0x00, 0x02, 0x1F, 0xD6,  # BR    X16
    ]  # fmt: off
    target = lief.MachO.Stub.target_info_t(lief.MachO.Header.CPU_TYPE.ARM64, 0)
    stub = lief.MachO.Stub(target, 0x3C47B08, raw_stub)
    assert (
        stub.target == 0x4B6A738
        if lief.__extended__
        else lief.lief_errors.require_extended_version
    )

    raw_stub = [
        # Address: 0x1804e4284
        0x50, 0x2B, 0x23, 0x90,  # ADRP  X16, #0x1C6A4C000
        0x10, 0x22, 0x13, 0x91,  # ADD   X16, X16, #0x4C8
        0x00, 0x02, 0x1F, 0xD6,  # BR    X16
    ]  # fmt: off
    target = lief.MachO.Stub.target_info_t(lief.MachO.Header.CPU_TYPE.ARM64, 0)
    stub = lief.MachO.Stub(target, 0x1804E4284, raw_stub)
    assert (
        stub.target == 0x1C6A4C4C8
        if lief.__extended__
        else lief.lief_errors.require_extended_version
    )

    raw_stub = [
        # Address: 0x2018310
        0x91, 0x08, 0x00, 0x90,  # ADRP x17, #1114112
        0x31, 0x02, 0x00, 0x91,  # ADD  X17, X17, #0
        0x30, 0x02, 0x40, 0xF9,  # LDR  X16, [X17]
        0x11, 0x0A, 0x1F, 0xD7,  # BRAA x16, x17
    ]  # fmt: off
    target = lief.MachO.Stub.target_info_t(lief.MachO.Header.CPU_TYPE.ARM64, 2)
    stub = lief.MachO.Stub(target, 0x2018310, raw_stub)
    assert (
        stub.target == 0x2128000
        if lief.__extended__
        else lief.lief_errors.require_extended_version
    )

    raw_stub = [
        # Address: 0x100175f2c
        0x1F, 0x20, 0x03, 0xD5,  # NOP
        0xD0, 0x13, 0x3B, 0x58,  # LDR X16, #483960
        0x00, 0x02, 0x1F, 0xD6,  # BR  X16
    ]  # fmt: off
    target = lief.MachO.Stub.target_info_t(lief.MachO.Header.CPU_TYPE.ARM64, 2)
    stub = lief.MachO.Stub(target, 0x100175F2C, raw_stub)
    assert (
        stub.target == 0x1001EC1A8
        if lief.__extended__
        else lief.lief_errors.require_extended_version
    )

    raw_stub = [
        # Address: 0x100003b14
        0xFF, 0x25, 0xE6, 0x44, 0x00, 0x00,  # jmp qword ptr [rip + 17638]
    ]  # fmt: off
    target = lief.MachO.Stub.target_info_t(lief.MachO.Header.CPU_TYPE.X86_64, 0)
    stub = lief.MachO.Stub(target, 0x100003B14, raw_stub)
    assert (
        stub.target == 0x100008000
        if lief.__extended__
        else lief.lief_errors.require_extended_version
    )
