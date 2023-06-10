import lief
from utils import get_sample

def test_config_1():
    config = lief.ELF.ParserConfig()

    config.parse_relocations = False
    config.parse_dyn_symbols = False
    config.parse_static_symbols = False
    config.parse_symbol_versions = False
    config.parse_notes = False
    config.count_mtd = lief.ELF.DYNSYM_COUNT_METHODS.SECTION

    fpath = get_sample("ELF/ELF64_AARCH64_piebinary_linker64.pie")
    elf = lief.ELF.parse(fpath, config)

    assert len(elf.relocations) == 0
    assert len(elf.symbols) == 0
    assert len(elf.dynamic_symbols) == 0
    assert len(elf.static_symbols) == 0
    assert len(elf.symbols_version) == 0
    assert len(elf.notes) == 0


def test_config_2():
    config = lief.ELF.ParserConfig()

    config.parse_relocations = True
    config.parse_dyn_symbols = False
    config.parse_static_symbols = False
    config.parse_symbol_versions = False
    config.parse_notes = False
    config.count_mtd = lief.ELF.DYNSYM_COUNT_METHODS.SECTION

    fpath = get_sample("ELF/ELF64_x86-64_binary_ld.bin")
    elf = lief.ELF.parse(fpath, config)

    assert len(elf.relocations) > 0
    assert len(elf.symbols) == 0
    assert len(elf.dynamic_symbols) == 0
    assert len(elf.static_symbols) == 0
    assert len(elf.symbols_version) == 0
    assert len(elf.notes) == 0

def test_config_3():
    config = lief.ELF.ParserConfig()

    config.parse_relocations = False
    config.parse_dyn_symbols = False
    config.parse_static_symbols = True
    config.parse_symbol_versions = False
    config.parse_notes = False
    config.count_mtd = lief.ELF.DYNSYM_COUNT_METHODS.SECTION

    fpath = get_sample("ELF/ELF64_x86-64_binary_hello-c-debug.bin")
    elf = lief.ELF.parse(fpath, config)

    assert len(elf.relocations) == 0
    assert len(elf.symbols) > 0
    assert len(elf.dynamic_symbols) == 0
    assert len(elf.static_symbols) > 0
    assert len(elf.symbols_version) == 0
    assert len(elf.notes) == 0
