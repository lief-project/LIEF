from pathlib import Path

import lief
from utils import parse_elf


def test_1124(tmp_path: Path):
    """
    Test for the PR #1124 in which there are multiple "empty" strings

    https://github.com/lief-project/LIEF/pull/1124
    """

    elf = parse_elf("ELF/cordic.ko")
    out = tmp_path / "cordic.ko"
    elf.write(out)

    cordic = lief.ELF.parse(out)
    assert cordic is not None
    symtab = cordic.symtab_symbols

    assert symtab[1].section is not None
    assert symtab[1].section.name == ".text"
    assert symtab[2].section is not None
    assert symtab[2].section.name == "__ksymtab_strings"
    assert symtab[35].name == "cordic_calc_iq"
