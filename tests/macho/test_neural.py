#!/usr/bin/env python
import lief
import pytest

from utils import get_sample, has_private_samples

@pytest.mark.skipif(not has_private_samples(), reason="needs private samples")
def test_personsemantics():
    """iPhone16,2 17.4.1 21E237 """
    target = lief.MachO.parse(get_sample("private/MachO/personsemantics-u8-v4.H16.espresso.hwx"))
    assert target is not None
    assert len(target) == 1
    macho = target.at(0)

    assert macho.commands[11].command == lief.MachO.LoadCommand.TYPE.LIEF_UNKNOWN
    assert bytes(macho.commands[11].data) == b'@\x00\x00\x00@\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb41\x00\x00\x00\x0028231623ec2b5d8f2f330980979387e0\x00\x00\x00\x00\x00\x00\x00\x00'
    assert macho.commands[18].command == lief.MachO.LoadCommand.TYPE.LIEF_UNKNOWN
    assert macho.commands[18].original_command == 64
    assert macho.header.magic == lief.MachO.MACHO_TYPES.NEURAL_MODEL
