from functools import lru_cache
from typing import cast

import lief
from utils import parse_elf


@lru_cache(maxsize=1)
def get_target() -> lief.ELF.Binary:
    return parse_elf("ELF/ELF32_x86_binary_all.bin")


def test_header():
    target = get_target()
    assert target.interpreter == "/lib/ld-linux.so.2"
    assert target.entrypoint == 0x774


def test_sections():
    target = get_target()
    assert len(target.sections) == 32

    assert target.has_section(".tdata")

    text_section = target.get_section(".text")
    assert text_section is not None

    assert text_section.type == lief.ELF.Section.TYPE.PROGBITS
    assert text_section.offset == 0x6D0
    assert text_section.virtual_address == 0x6D0
    assert text_section.size == 0x271
    assert text_section.alignment == 16
    assert text_section.has(lief.ELF.Section.FLAGS.ALLOC)
    assert text_section.has(lief.ELF.Section.FLAGS.EXECINSTR)


def test_segments():
    segments = get_target().segments
    assert len(segments) == 10

    load_0 = segments[2]
    load_1 = segments[3]

    assert load_0.type == lief.ELF.Segment.TYPE.LOAD
    assert load_0.file_offset == 0
    assert load_0.virtual_address == 0
    assert load_0.physical_size == 0x00B34
    assert load_0.virtual_size == 0x00B34
    assert load_0.flags == lief.ELF.Segment.FLAGS.R | lief.ELF.Segment.FLAGS.X

    assert load_1.type == lief.ELF.Segment.TYPE.LOAD
    assert load_1.file_offset == 0x000ED8
    assert load_1.virtual_address == 0x00001ED8
    assert load_1.physical_address == 0x00001ED8
    assert load_1.physical_size == 0x00148
    assert load_1.virtual_size == 0x0014C
    assert load_1.flags == lief.ELF.Segment.FLAGS.R | lief.ELF.Segment.FLAGS.W


def test_dynamic():
    target = get_target()
    entries = target.dynamic_entries
    assert len(entries) == 28
    lib_entry = cast(lief.ELF.DynamicEntryLibrary, entries[0])
    assert lib_entry.name == "libc.so.6"

    array_entry = cast(lief.ELF.DynamicEntryArray, entries[3])
    assert array_entry.array == [2208, 1782]
    flags1_entry = target[lief.ELF.DynamicEntry.TAG.FLAGS_1]
    assert flags1_entry is not None
    assert flags1_entry.value == 0x8000000


def test_relocations():
    target = get_target()
    dynamic_relocations = target.dynamic_relocations
    pltgot_relocations = target.pltgot_relocations

    assert len(dynamic_relocations) == 10
    assert len(pltgot_relocations) == 3

    assert dynamic_relocations[0].address == 0x00001EDC
    assert dynamic_relocations[8].symbol is not None
    assert dynamic_relocations[8].symbol.name == "__gmon_start__"
    assert dynamic_relocations[9].address == 0x00001FFC

    assert pltgot_relocations[1].address == 0x00002010
    assert pltgot_relocations[1].symbol is not None
    assert pltgot_relocations[1].symbol.name == "puts"
    assert pltgot_relocations[1].info == 4


def test_symbols():
    target = get_target()
    dynamic_symbols = target.dynamic_symbols
    symtab_symbols = target.symtab_symbols

    assert len(dynamic_symbols) == 27
    assert len(symtab_symbols) == 78

    first = target.get_dynamic_symbol("first")
    assert first is not None
    assert first.value == 0x000008A9
    assert first.symbol_version is not None
    assert first.symbol_version.value == 0x8002
    assert first.symbol_version.symbol_version_auxiliary is not None
    assert first.symbol_version.symbol_version_auxiliary.name == "LIBSIMPLE_1.0"

    dtor = target.get_symtab_symbol("__cxa_finalize@@GLIBC_2.1.3")
    assert dtor is not None
    assert dtor.value == 00000000

    symbol_version_definition = target.symbols_version_definition
    symbols_version_requirement = target.symbols_version_requirement
    symbols_version = target.symbols_version

    assert len(symbol_version_definition) == 2
    assert len(symbols_version_requirement) == 1
    assert len(symbols_version) == 27

    assert symbol_version_definition[0].hash == 0x63CA0E
    assert symbol_version_definition[0].version == 1
    assert symbol_version_definition[0].flags == 1
    assert symbol_version_definition[0].auxiliary_symbols[0].name == "all-32.bin"

    assert symbol_version_definition[1].auxiliary_symbols[0].name == "LIBSIMPLE_1.0"

    assert symbols_version_requirement[0].name == "libc.so.6"
    assert symbols_version_requirement[0].version == 1

    assert symbols_version[0].value == 0


def test_notes():
    target = get_target()
    notes = target.notes
    assert len(notes) == 2

    note_abi = notes[0]
    assert isinstance(note_abi, lief.ELF.NoteAbi)
    assert note_abi.abi == lief.ELF.NoteAbi.ABI.LINUX
    assert list(notes[0].description) == [
        0,
        0,
        0,
        0,
        3,
        0,
        0,
        0,
        2,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
    assert note_abi.name == "GNU"
    assert note_abi.type == lief.ELF.Note.TYPE.GNU_ABI_TAG
    assert note_abi.version == [3, 2, 0]


def test_symbols_sections():
    """
    Related to this issue: https://github.com/lief-project/LIEF/issues/841
    """
    elf = parse_elf("ELF/ELF64_x86-64_binary_all.bin")
    main = elf.get_symtab_symbol("main")
    assert main is not None
    assert main.section is not None
    assert main.section.name == ".text"

    gmon_sym = elf.get_symtab_symbol("__gmon_start__")
    assert gmon_sym is not None
    assert gmon_sym.section is None
    fini_sym = elf.get_symtab_symbol("_fini")
    assert fini_sym is not None
    assert fini_sym.section is not None
    assert fini_sym.section.name == ".fini"
