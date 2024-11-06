import lief
from pathlib import Path

from utils import get_sample

def test_1124(tmp_path: Path):
    """
    Test for the PR #1124 in which there are multiple "empty" strings

    https://github.com/lief-project/LIEF/pull/1124
    """

    elf = lief.ELF.parse(get_sample("ELF/cordic.ko"))
    out = tmp_path / "cordic.ko"
    elf.write(out.as_posix())

    cordic = lief.ELF.parse(out)
    symtab = cordic.symtab_symbols

    assert symtab[1].section.name == ".text"
    assert symtab[2].section.name == "__ksymtab_strings"
    assert symtab[35].name == "cordic_calc_iq"
