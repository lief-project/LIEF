from pathlib import Path

import lief
import pytest
from utils import parse_macho


def test_945():
    target = parse_macho("MachO/python3_issue_476.bin").at(0)
    assert target is not None
    segments = target.segments

    assert all(isinstance(s, lief.MachO.SegmentCommand) for s in segments)
    assert "__LINKEDIT" in {s.name for s in segments}

    for load_command in target.commands:
        if load_command.command in (
            lief.MachO.LoadCommand.TYPE.SEGMENT,
            lief.MachO.LoadCommand.TYPE.SEGMENT_64,
        ):
            assert isinstance(load_command, lief.MachO.SegmentCommand)


def test_993(tmp_path: Path):
    target = parse_macho("MachO/alivcffmpeg_armv7.dylib")
    out = Path(tmp_path) / "issue_993.dylib"
    target.write(out)

    new = lief.MachO.parse(out)
    assert new is not None
    not_err, msg = lief.MachO.check_layout(new)
    assert not_err, msg


def test_1087():
    target = parse_macho("MachO/fbcb7580db7bc04d695c3fd0308bb344_issue_1087").at(0)
    assert target is not None
    assert target.offset_to_virtual_address(0x42DAE) == 0x100042DAE


def test_endianness():
    target = parse_macho("MachO/macho-issue-1110.bin").at(0)
    assert target is not None

    assert len(target.segments) == 3


def test_1130(tmp_path: Path):
    target = parse_macho("MachO/issue_1130.macho").at(0)
    assert target is not None
    target.shift(0x4000)

    output = tmp_path / "new.macho"
    target.write(output)

    fat = lief.MachO.parse(output)
    assert fat is not None
    new = fat.at(0)
    assert new is not None
    assert lief.MachO.check_layout(new)[0]

    data_seg = new.get_segment("__DATA")
    assert data_seg is not None
    assert data_seg.virtual_address == 0x100008000


def test_1132():
    # Check if cache is updated that is used by segment_from_offset
    binary = parse_macho("MachO/FAT_MachO_arm-arm64-binary-helloworld.bin").take(
        lief.MachO.Header.CPU_TYPE.ARM64
    )
    assert binary is not None

    text_segment = binary.get_segment("__TEXT")
    assert text_segment is not None
    binary.extend_segment(text_segment, 0x10000)

    def can_cache_segment(seg):
        return seg.file_offset > 0 or seg.file_size > 0 or seg.name == "__TEXT"

    for seg in binary.segments:
        if can_cache_segment(seg):
            assert binary.segment_from_offset(seg.file_offset) == seg


@pytest.mark.private
def test_issue_ntype(tmp_path: Path):
    macho = parse_macho("private/MachO/amfid.arm64e").at(0)
    assert macho is not None
    output = tmp_path / "amfid_out.arm64e"

    assert macho.symbols[0].raw_type == 60

    macho.write(output)
    fat = lief.MachO.parse(output)
    assert fat is not None
    new = fat.at(0)
    assert new is not None
    assert new.symbols[0].raw_type == 60
