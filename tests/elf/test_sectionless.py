import lief
from utils import get_sample

TARGET = lief.ELF.parse(get_sample('ELF/ELF64_x86-64_binary_rvs.bin'), lief.ELF.DYNSYM_COUNT_METHODS.HASH)

def test_symbols():
    symbols = TARGET.dynamic_symbols
    assert len(symbols) == 10

    assert symbols[2].name == "_IO_putc"

def test_relocations():
    relocations = TARGET.relocations
    assert len(relocations) == 10

    assert relocations[0].symbol.name == "__gmon_start__"
