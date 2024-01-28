import lief
from utils import get_sample

config = lief.ELF.ParserConfig()
config.count_mtd = lief.ELF.ParserConfig.DYNSYM_COUNT.HASH

TARGET = lief.ELF.parse(get_sample('ELF/ELF64_x86-64_binary_rvs.bin'), config)

def test_symbols():
    symbols = TARGET.dynamic_symbols
    assert len(symbols) == 10

    assert symbols[2].name == "_IO_putc"

def test_relocations():
    relocations = TARGET.relocations
    assert len(relocations) == 10

    assert relocations[0].symbol.name == "__gmon_start__"
