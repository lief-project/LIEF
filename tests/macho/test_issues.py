#!/usr/bin/env python
import lief
from utils import get_sample
from pathlib import Path

def test_945():
    target = lief.MachO.parse(get_sample("MachO/python3_issue_476.bin")).at(0)
    segments = target.segments

    assert all(isinstance(s, lief.MachO.SegmentCommand) for s in segments)
    assert "__LINKEDIT" in {s.name for s in segments}

    for load_command in target.commands:
        if load_command.command in (lief.MachO.LoadCommand.TYPE.SEGMENT, lief.MachO.LoadCommand.TYPE.SEGMENT_64):
            assert isinstance(load_command, lief.MachO.SegmentCommand)

def test_993(tmp_path):
    target = lief.MachO.parse(get_sample("MachO/alivcffmpeg_armv7.dylib"))
    out = Path(tmp_path) / "issue_993.dylib"
    target.write(out.as_posix())

    new = lief.MachO.parse(out)
    not_err, msg = lief.MachO.check_layout(new)
    assert not_err, msg

def test_1087():
    target = lief.MachO.parse(get_sample("MachO/fbcb7580db7bc04d695c3fd0308bb344_issue_1087")).at(0)
    assert target.offset_to_virtual_address(0x42dae) == 0x100042dae

def test_endianness():
    target = lief.MachO.parse(get_sample("MachO/macho-issue-1110.bin")).at(0)

    assert len(target.segments) == 3

def test_1130(tmp_path: Path):
    target = lief.MachO.parse(get_sample("MachO/issue_1130.macho")).at(0)
    target.shift(0x4000)

    output = tmp_path / "new.macho"
    target.write(output.as_posix())

    new = lief.MachO.parse(output).at(0)
    assert lief.MachO.check_layout(new)[0]

    assert new.get_segment("__DATA").virtual_address == 0x100008000
