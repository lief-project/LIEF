#!/usr/bin/env python
import lief
from utils import get_sample

lief.logging.set_level(lief.logging.LEVEL.INFO)

def test_linkedit(tmp_path):
    original = lief.MachO.parse(get_sample('MachO/MachO64_x86-64_binary_id.bin')).at(0)
    output = f"{tmp_path}/test_id.bin"

    config = lief.MachO.Builder.config_t()
    config.linkedit = False

    lief.MachO.Builder.write(original, output, config)

    modified = lief.MachO.parse(output).at(0)

    checked, err = lief.MachO.check_layout(modified)
    assert checked, err

def test_fat(tmp_path):
    original = lief.MachO.parse(get_sample('MachO/FAT_MachO_x86-x86-64-binary_fatall.bin')).at(0)
    output = f"{tmp_path}/test_fatall.bin"

    config = lief.MachO.Builder.config_t()
    config.linkedit = False

    lief.MachO.Builder.write(original, output, config)

    modified = lief.MachO.parse(output).at(0)

    checked, err = lief.MachO.check_layout(modified)
    assert checked, err
