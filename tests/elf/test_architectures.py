import lief
from utils import get_sample

def test_s390():
    s390 = lief.ELF.parse(get_sample("ELF/elf_reader.s390.elf"))
    assert len(s390.segments) == 10
    assert len(s390.sections) == 32
    assert len(s390.dynamic_symbols) == 278
    assert len(s390.dynamic_entries) == 27

def test_xtensa():
    xtensa = lief.ELF.parse(get_sample("ELF/elf_reader.xtensa.elf"))
    assert len(xtensa.segments) == 10
    assert len(xtensa.sections) == 30
    assert len(xtensa.dynamic_symbols) == 247
    assert len(xtensa.dynamic_entries) == 25

def test_mips():
    mips = lief.ELF.parse(get_sample("ELF/elf_reader.mips.elf"))
    assert len(mips.segments) == 12
    assert len(mips.sections) == 39
    assert len(mips.dynamic_symbols) == 450
    assert len(mips.dynamic_entries) == 36

def test_riscv64():
    riscv64 = lief.ELF.parse(get_sample("ELF/elf_reader.riscv64.elf"))
    assert len(riscv64.segments) == 10
    assert len(riscv64.sections) == 30
    assert len(riscv64.dynamic_symbols) == 439
    assert len(riscv64.dynamic_entries) == 29

def test_riscv32():
    riscv32 = lief.ELF.parse(get_sample("ELF/elf_reader.riscv32.elf"))
    assert len(riscv32.segments) == 10
    assert len(riscv32.sections) == 30
    assert len(riscv32.dynamic_symbols) == 445
    assert len(riscv32.dynamic_entries) == 29

def test_ppc64le():
    ppc64le = lief.ELF.parse(get_sample("ELF/elf_reader.ppc64le.elf"))
    assert len(ppc64le.segments) == 10
    assert len(ppc64le.sections) == 32
    assert len(ppc64le.dynamic_symbols) == 246
    assert len(ppc64le.dynamic_entries) == 29

def test_hexagon():
    hexagon = lief.ELF.parse(get_sample("ELF/modem.hexagon.elf"))
    assert len(hexagon.segments) == 7
