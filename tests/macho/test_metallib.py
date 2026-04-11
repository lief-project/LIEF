from pathlib import Path

import lief
from utils import parse_macho


def test_binary_metallib(tmp_path: Path):
    fat = parse_macho("MachO/binary.metallib")
    assert fat is not None
    assert len(fat) == 15

    macho = fat.at(0)
    assert macho is not None

    assert macho.header.file_type == lief.MachO.Header.FILE_TYPE.GPU_EXECUTE
    notes = macho.notes
    assert len(notes) == 8

    assert notes[0].note_offset == 0x380
    assert notes[0].note_size == 0x10
    assert notes[0].owner_str == "AIR_METALLIB"

    assert notes[7].note_offset == 0x3F0
    assert notes[7].note_size == 0x10
    assert notes[7].owner_str == "AIR_STRTABLE"

    out_path = tmp_path / "out.macho"

    macho.write(out_path)
    _fat = lief.MachO.parse(out_path)
    assert _fat is not None
    new = _fat.at(0)
    assert new is not None
    assert len(new.notes) == 8
