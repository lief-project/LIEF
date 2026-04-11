from pathlib import Path

import lief
import pytest
from utils import get_sample


@pytest.mark.parametrize(
    "elf", ["ELF/ELF64_x86-64_binary_all.bin", "ELF/ELF32_x86_binary_all.bin"]
)
def test_equal(tmp_path: Path, elf):
    infile = get_sample(elf)
    inelf = lief.ELF.parse(infile)
    assert inelf is not None
    output = tmp_path / Path(infile).name
    inelf.write(output)
    newelf = lief.ELF.parse(output)
    assert newelf is not None

    assert inelf.header == newelf.header

    for lhs, rhs in zip(inelf.sections, newelf.sections):
        assert lhs == rhs

    for lhs, rhs in zip(inelf.segments, newelf.segments):
        assert lhs == rhs

    for lhs, rhs in zip(inelf.relocations, newelf.relocations):
        assert lhs == rhs

    for lhs, rhs in zip(inelf.symbols, newelf.symbols):
        assert lhs == rhs

    for lhs, rhs in zip(inelf.dynamic_entries, newelf.dynamic_entries):
        assert lhs == rhs
