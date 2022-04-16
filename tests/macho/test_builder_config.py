#!/usr/bin/env python
import lief
from utils import get_sample, is_apple_m1, is_osx, sign, chmod_exe, is_github_ci

lief.logging.set_level(lief.logging.LOGGING_LEVEL.INFO)


def test_linkedit(tmp_path):
    original = lief.parse(get_sample('MachO/MachO64_x86-64_binary_id.bin'))
    output = f"{tmp_path}/test_id.bin"

    config = lief.MachO.Builder.config_t()
    config.linkedit = False

    lief.MachO.Builder.write(original, output, config)

    modified = lief.parse(output)

    checked, err = lief.MachO.check_layout(modified)
    assert checked, err

def test_fat(tmp_path):
    original = lief.parse(get_sample('MachO/FAT_MachO_x86-x86-64-binary_fatall.bin'))
    output = f"{tmp_path}/test_fatall.bin"

    config = lief.MachO.Builder.config_t()
    config.linkedit = False

    lief.MachO.Builder.write(original, output, config)

    modified = lief.parse(output)

    checked, err = lief.MachO.check_layout(modified)
    assert checked, err
