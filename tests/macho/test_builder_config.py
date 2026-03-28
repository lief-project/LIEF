#!/usr/bin/env python
import lief
from utils import get_sample
from pathlib import Path
def test_linkedit(tmp_path: Path):
    original = lief.MachO.parse(get_sample('MachO/MachO64_x86-64_binary_id.bin')).at(0)
    output = tmp_path / "test_id.bin"

    config = lief.MachO.Builder.config_t()
    config.linkedit = False

    original.write(output, config)

    modified = lief.MachO.parse(output).at(0)

    checked, err = lief.MachO.check_layout(modified)
    assert checked, err

def test_fat(tmp_path: Path):
    original = lief.MachO.parse(get_sample('MachO/FAT_MachO_x86-x86-64-binary_fatall.bin')).at(0)
    output = tmp_path / "test_fatall.bin"

    config = lief.MachO.Builder.config_t()
    config.linkedit = False

    original.write(output, config)

    modified = lief.MachO.parse(output).at(0)

    checked, err = lief.MachO.check_layout(modified)
    assert checked, err
