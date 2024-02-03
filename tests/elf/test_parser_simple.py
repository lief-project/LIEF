import lief
from utils import get_sample

TARGET = lief.ELF.parse(get_sample('ELF/ELF32_x86_binary_all.bin'))

def test_header():
    assert TARGET.interpreter == "/lib/ld-linux.so.2"
    assert TARGET.entrypoint == 0x774

def test_sections():
    assert len(TARGET.sections) == 32

    assert TARGET.has_section(".tdata")

    text_section = TARGET.get_section(".text")

    assert text_section.type == lief.ELF.Section.TYPE.PROGBITS
    assert text_section.offset == 0x6D0
    assert text_section.virtual_address == 0x6D0
    assert text_section.size == 0x271
    assert text_section.alignment == 16
    assert lief.ELF.Section.FLAGS.ALLOC in text_section
    assert lief.ELF.Section.FLAGS.EXECINSTR in text_section

def test_segments():
    segments = TARGET.segments
    assert len(segments) == 10

    LOAD_0 = segments[2]
    LOAD_1 = segments[3]

    assert LOAD_0.type == lief.ELF.Segment.TYPE.LOAD
    assert LOAD_0.file_offset == 0
    assert LOAD_0.virtual_address == 0
    assert LOAD_0.physical_size == 0x00b34
    assert LOAD_0.virtual_size == 0x00b34
    assert int(LOAD_0.flags) == lief.ELF.Segment.FLAGS.R | lief.ELF.Segment.FLAGS.X

    assert LOAD_1.type == lief.ELF.Segment.TYPE.LOAD
    assert LOAD_1.file_offset == 0x000ed8
    assert LOAD_1.virtual_address == 0x00001ed8
    assert LOAD_1.physical_address == 0x00001ed8
    assert LOAD_1.physical_size == 0x00148
    assert LOAD_1.virtual_size == 0x0014c
    assert int(LOAD_1.flags) == lief.ELF.Segment.FLAGS.R | lief.ELF.Segment.FLAGS.W

def test_dynamic():
    entries = TARGET.dynamic_entries
    assert len(entries) == 28
    lib_entry: lief.ELF.DynamicEntryLibrary = entries[0]
    assert lib_entry.name == "libc.so.6"

    array_entry: lief.ELF.DynamicEntryArray = entries[3]
    assert array_entry.array == [2208, 1782]
    assert TARGET[lief.ELF.DynamicEntry.TAG.FLAGS_1].value == 0x8000000

def test_relocations():
    dynamic_relocations = TARGET.dynamic_relocations
    pltgot_relocations = TARGET.pltgot_relocations

    assert len(dynamic_relocations) == 10
    assert len(pltgot_relocations) == 3

    assert dynamic_relocations[0].address == 0x00001edc
    assert dynamic_relocations[8].symbol.name == "__gmon_start__"
    assert dynamic_relocations[9].address == 0x00001ffc

    assert pltgot_relocations[1].address == 0x00002010
    assert pltgot_relocations[1].symbol.name == "puts"
    assert pltgot_relocations[1].info == 4

def test_symbols():
    dynamic_symbols = TARGET.dynamic_symbols
    symtab_symbols  = TARGET.symtab_symbols

    assert len(dynamic_symbols) == 27
    assert len(symtab_symbols) == 78

    first = TARGET.get_dynamic_symbol("first")
    assert first.value == 0x000008a9
    assert first.symbol_version.value == 0x8002
    assert first.symbol_version.symbol_version_auxiliary.name == "LIBSIMPLE_1.0"

    dtor = TARGET.get_symtab_symbol("__cxa_finalize@@GLIBC_2.1.3")
    assert dtor.value == 00000000

    symbol_version_definition   = TARGET.symbols_version_definition
    symbols_version_requirement = TARGET.symbols_version_requirement
    symbols_version             = TARGET.symbols_version

    assert len(symbol_version_definition) == 2
    assert len(symbols_version_requirement) == 1
    assert len(symbols_version) == 27

    assert symbol_version_definition[0].hash == 0x63ca0e
    assert symbol_version_definition[0].version == 1
    assert symbol_version_definition[0].flags == 1
    assert symbol_version_definition[0].auxiliary_symbols[0].name == "all-32.bin"

    assert symbol_version_definition[1].auxiliary_symbols[0].name == "LIBSIMPLE_1.0"

    assert symbols_version_requirement[0].name == "libc.so.6"
    assert symbols_version_requirement[0].version == 1

    assert symbols_version[0].value == 0

def test_notes():
    notes = TARGET.notes
    assert len(notes) == 2

    assert isinstance(notes[0], lief.ELF.NoteAbi)
    assert notes[0].abi == lief.ELF.NoteAbi.ABI.LINUX
    assert list(notes[0].description) == [0, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]
    assert notes[0].name == "GNU"
    assert notes[0].type == lief.ELF.Note.TYPE.GNU_ABI_TAG
    assert notes[0].version == [3, 2, 0]

def test_symbols_sections():
    """
    Related to this issue: https://github.com/lief-project/LIEF/issues/841
    """
    elf = lief.ELF.parse(get_sample('ELF/ELF64_x86-64_binary_all.bin'))
    main = elf.get_symtab_symbol("main")
    assert main.section is not None
    assert main.section.name == ".text"

    assert elf.get_symtab_symbol("__gmon_start__").section is None
    assert elf.get_symtab_symbol("_fini").section.name == ".fini"
