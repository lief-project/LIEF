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
