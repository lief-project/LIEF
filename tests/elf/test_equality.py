#!/usr/bin/env python
import pytest
from pathlib import Path

import lief
from utils import get_sample

@pytest.mark.parametrize("elf", [
    "ELF/ELF64_x86-64_binary_all.bin",
    "ELF/ELF32_x86_binary_all.bin"
])
def test_equal(tmp_path: Path, elf):
    inelf = lief.parse(get_sample(elf))
    output = tmp_path / Path(inelf.name).name
    inelf.write(output.as_posix())
    newelf = lief.parse(output.as_posix())

    assert inelf.header == newelf.header

    for l, r in zip(inelf.sections, newelf.sections):
        assert l == r

    for l, r in zip(inelf.segments, newelf.segments):
        assert l == r

    for l, r in zip(inelf.relocations, newelf.relocations):
        assert l == r

    for l, r in zip(inelf.symbols, newelf.symbols):
        assert l == r

    for l, r in zip(inelf.dynamic_entries, newelf.dynamic_entries):
        assert l == r
