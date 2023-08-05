#!/usr/bin/env python
import lief
from utils import get_sample

def test_945():
    target = lief.MachO.parse(get_sample("MachO/python3_issue_476.bin")).at(0)
    segments = target.segments

    assert all(isinstance(s, lief.MachO.SegmentCommand) for s in segments)
    assert "__LINKEDIT" in {s.name for s in segments}

    for load_command in target.commands:
        if load_command.command in (lief.MachO.LOAD_COMMAND_TYPES.SEGMENT, lief.MachO.LOAD_COMMAND_TYPES.SEGMENT_64):
            assert isinstance(load_command, lief.MachO.SegmentCommand)
