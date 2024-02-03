import lief
from utils import get_sample

def test_config_1():
    config = lief.ELF.ParserConfig()

    config.parse_relocations = False
    config.parse_dyn_symbols = False
    config.parse_symtab_symbols = False
    config.parse_symbol_versions = False
    config.parse_notes = False
    config.count_mtd = lief.ELF.ParserConfig.DYNSYM_COUNT.SECTION

    fpath = get_sample("ELF/ELF64_AARCH64_piebinary_linker64.pie")
    elf = lief.ELF.parse(fpath, config)

    assert len(elf.relocations) == 0
    assert len(elf.symbols) == 0
    assert len(elf.dynamic_symbols) == 0
    assert len(elf.symtab_symbols) == 0
    assert len(elf.symbols_version) == 0
    assert len(elf.notes) == 0


def test_config_2():
    config = lief.ELF.ParserConfig()

    config.parse_relocations = True
    config.parse_dyn_symbols = False
    config.parse_symtab_symbols = False
    config.parse_symbol_versions = False
    config.parse_notes = False
    config.count_mtd = lief.ELF.ParserConfig.DYNSYM_COUNT.SECTION

    fpath = get_sample("ELF/ELF64_x86-64_binary_ld.bin")
    elf = lief.ELF.parse(fpath, config)

    assert len(elf.relocations) > 0
    assert len(elf.symbols) == 0
    assert len(elf.dynamic_symbols) == 0
    assert len(elf.symtab_symbols) == 0
    assert len(elf.symbols_version) == 0
    assert len(elf.notes) == 0

def test_config_3():
    config = lief.ELF.ParserConfig()

    config.parse_relocations = False
    config.parse_dyn_symbols = False
    config.parse_symtab_symbols = True
    config.parse_symbol_versions = False
    config.parse_notes = False
    config.count_mtd = lief.ELF.ParserConfig.DYNSYM_COUNT.SECTION

    fpath = get_sample("ELF/ELF64_x86-64_binary_hello-c-debug.bin")
    elf = lief.ELF.parse(fpath, config)

    assert len(elf.relocations) == 0
    assert len(elf.symbols) > 0
    assert len(elf.dynamic_symbols) == 0
    assert len(elf.symtab_symbols) > 0
    assert len(elf.symbols_version) == 0
    assert len(elf.notes) == 0

def test_config_no_overlay():
    config = lief.ELF.ParserConfig()

    config.parse_overlay = False
    fpath = get_sample("ELF/batch-x86-64/test.dart.bin")
    assert len(lief.ELF.parse(fpath).overlay) > 0
    elf = lief.ELF.parse(fpath)
    assert elf.has_overlay
    elf = lief.ELF.parse(fpath, config)
    assert len(elf.overlay) == 0
