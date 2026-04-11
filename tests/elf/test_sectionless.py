from functools import lru_cache

import lief
from utils import parse_elf


@lru_cache(maxsize=1)
def _get_target() -> lief.ELF.Binary:
    config = lief.ELF.ParserConfig()
    config.count_mtd = lief.ELF.ParserConfig.DYNSYM_COUNT.HASH
    return parse_elf("ELF/ELF64_x86-64_binary_rvs.bin", config)


def test_symbols():
    symbols = _get_target().dynamic_symbols
    assert len(symbols) == 10

    assert symbols[2].name == "_IO_putc"


def test_relocations():
    relocations = _get_target().relocations
    assert len(relocations) == 10

    assert relocations[0].symbol is not None
    assert relocations[0].symbol.name == "__gmon_start__"
