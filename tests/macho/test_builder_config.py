from pathlib import Path

import lief
from utils import parse_macho


def test_linkedit(tmp_path: Path):
    original = parse_macho("MachO/MachO64_x86-64_binary_id.bin").at(0)
    assert original is not None
    output = tmp_path / "test_id.bin"

    config = lief.MachO.Builder.config_t()
    config.linkedit = False

    original.write(output, config)

    fat = lief.MachO.parse(output)
    assert fat is not None
    modified = fat.at(0)
    assert modified is not None

    checked, err = lief.MachO.check_layout(modified)
    assert checked, err


def test_fat(tmp_path: Path):
    original = parse_macho("MachO/FAT_MachO_x86-x86-64-binary_fatall.bin").at(0)
    assert original is not None
    output = tmp_path / "test_fatall.bin"

    config = lief.MachO.Builder.config_t()
    config.linkedit = False

    original.write(output, config)

    fat = lief.MachO.parse(output)
    assert fat is not None
    modified = fat.at(0)
    assert modified is not None

    checked, err = lief.MachO.check_layout(modified)
    assert checked, err
