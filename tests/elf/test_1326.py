from pathlib import Path

import lief
import pytest
from utils import check_layout, parse_elf


@pytest.mark.private
def test_issue_1326(tmp_path: Path):
    elf = parse_elf("private/ELF/kvrocks2redis")
    check_layout(elf)

    notes = elf.notes
    assert len(notes) == 6
    assert notes[5].name == "stapsdt"

    for n in elf.notes:
        print(type(n))

    config = lief.ELF.Builder.config_t()
    config.force_relocate = True

    out_path = tmp_path / "kvrocks2redis"
    elf.write(out_path, config)
    new_elf = parse_elf(out_path)
    check_layout(new_elf)

    notes = new_elf.notes
    assert len(notes) == 6
    assert notes[5].name == "stapsdt"
