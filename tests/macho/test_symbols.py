import re
from pathlib import Path

import lief
import pytest
from utils import get_sample, is_osx, parse_macho

from .test_builder import run_program


def test_unexport(tmp_path: Path):
    bin_path = Path(get_sample("MachO/MachO64_x86-64_binary_sym2remove.bin"))
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    original = fat.at(0)
    assert original is not None
    output = tmp_path / bin_path.name
    exported = {s.name for s in original.symbols if s.has_export_info}

    assert "_remove_me" in exported

    original.unexport("_remove_me")

    original.write(output)
    new_fat = lief.MachO.parse(output)
    assert new_fat is not None
    new = new_fat.at(0)
    assert new is not None

    exported = {s.name for s in new.symbols if s.has_export_info}
    assert "_remove_me" not in exported

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_osx():
        assert run_program(bin_path)
        stdout = run_program(output)

        lief.logging.info(stdout)
        assert re.search(r"Hello World", stdout) is not None


def test_rm_symbols(tmp_path: Path):
    bin_path = Path(get_sample("MachO/MachO64_x86-64_binary_sym2remove.bin"))
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    original = fat.at(0)
    assert original is not None
    output = tmp_path / bin_path.name

    for s in ["__ZL6BANNER", "_remove_me"]:
        assert original.can_remove_symbol(s)
        original.remove_symbol(s)

    original.write(output)
    new_fat = lief.MachO.parse(output)
    assert new_fat is not None
    new = new_fat.at(0)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    assert new.get_symbol("__ZL6BANNER") is None
    assert new.get_symbol("_remove_me") is None

    if is_osx():
        assert run_program(bin_path)
        stdout = run_program(output)

        lief.logging.info(stdout)
        assert re.search(r"Hello World", stdout) is not None


def test_dynsym_command():
    macho = parse_macho("MachO/MachO64_x86-64_binary_all.bin").at(0)
    assert macho is not None

    dynsym = macho.dynamic_symbol_command
    assert dynsym is not None

    assert dynsym.idx_local_symbol == 0
    assert dynsym.nb_local_symbols == 1

    assert dynsym.idx_external_define_symbol == 1
    assert dynsym.nb_external_define_symbols == 6

    assert dynsym.idx_undefined_symbol == 7
    assert dynsym.nb_undefined_symbols == 3

    assert dynsym.toc_offset == 0
    assert dynsym.nb_toc == 0
    assert dynsym.module_table_offset == 0
    assert dynsym.nb_module_table == 0
    assert dynsym.external_reference_symbol_offset == 0
    assert dynsym.nb_external_reference_symbols == 0
    assert dynsym.indirect_symbol_offset == 0x2168
    assert dynsym.nb_indirect_symbols == 4
    assert dynsym.external_relocation_offset == 0
    assert dynsym.nb_external_relocations == 0
    assert dynsym.local_relocation_offset == 0
    assert dynsym.nb_local_relocations == 0

    for sym in dynsym.indirect_symbols:
        lief.logging.info(sym)

    indirect_symbols = dynsym.indirect_symbols
    assert len(indirect_symbols) == 4

    assert indirect_symbols[0].name == "_printf"
    assert indirect_symbols[1].name == "dyld_stub_binder"

    assert indirect_symbols[2].name == ""
    assert indirect_symbols[2].category == lief.MachO.Symbol.CATEGORY.INDIRECT_ABS

    assert indirect_symbols[3].name == "_printf"


def test_symbol_library():
    macho = parse_macho("MachO/macho-arm64-osx-vtable-chained-fixups.bin").at(0)
    assert macho is not None
    symbols = macho.symbols
    assert len(symbols) == 16

    bindings = list(macho.bindings)
    assert len(bindings) == 3

    sym0 = bindings[0].symbol
    assert sym0 is not None
    assert sym0.name == "_printf"
    assert sym0.is_external
    lib0 = sym0.library
    assert lib0 is not None
    assert lib0.name == "/usr/lib/libSystem.B.dylib"
    assert sym0.library_ordinal == 2

    sym1 = bindings[1].symbol
    assert sym1 is not None
    assert sym1.is_external
    assert sym1.name == "__ZTVN10__cxxabiv117__class_type_infoE"
    lib1 = sym1.library
    assert lib1 is not None
    assert lib1.name == "/usr/lib/libc++.1.dylib"
    assert sym1.library_ordinal == 1

    sym2 = bindings[2].symbol
    assert sym2 is not None
    assert sym2.is_external
    assert sym2.name == "__ZTVN10__cxxabiv120__si_class_type_infoE"
    lib2 = sym2.library
    assert lib2 is not None
    assert lib2.name == "/usr/lib/libc++.1.dylib"
    assert sym2.library_ordinal == 1


@pytest.mark.skipif(not lief.__extended__, reason="needs LIEF extended")
def test_demangling():
    macho = parse_macho("MachO/FAT_MachO_x86_x86-64_library_libc++abi.dylib").at(0)
    assert macho is not None

    assert (
        macho.symbols[1].demangled_name
        == "void __cxxabiv1::(anonymous namespace)::demangle<__cxxabiv1::(anonymous namespace)::Db>(char const*, char const*, __cxxabiv1::(anonymous namespace)::Db&, int&)"
    )
    assert macho.symbols[486].demangled_name == "___cxa_deleted_virtual"


def test_symbol_shift():
    bin_path = Path(get_sample("MachO/MachO64_x86-64_binary_sym2remove.bin"))
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    macho = fat.at(0)
    assert macho is not None

    shift = 0x4000
    loadcommands_end = (
        macho.imagebase + 32 + macho.header.sizeof_cmds
    )  # sizeof(mach_header_64) + size of load command table

    def get_shifted_symbol(sym):
        value = sym.value
        if value > loadcommands_end:
            value += shift
        return (sym.name, value)

    check_symbols = {
        get_shifted_symbol(sym)
        for sym in macho.symbols
        if sym.raw_type & 0x0E == lief.MachO.Symbol.TYPE.SECTION
    }
    macho.shift(shift)
    shifted_symbols = {
        (sym.name, sym.value)
        for sym in macho.symbols
        if sym.raw_type & 0x0E == lief.MachO.Symbol.TYPE.SECTION
    }

    assert shifted_symbols == check_symbols


def test_exports_after_shift():
    bin_path = Path(get_sample("MachO/MachO64_AArch64_weak-sym.bin"))
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    macho = fat.at(0)
    assert macho is not None
    dyld_info = macho.dyld_info
    assert dyld_info is not None

    shift = 0x10000
    loadcommands_end = (
        32 + macho.header.sizeof_cmds
    )  # sizeof(mach_header_64) + size of load command table

    def get_shifted_export(e):
        address = e.address
        if address > loadcommands_end:
            address += shift
        return address

    expected_exports_addrs = [get_shifted_export(e) for e in dyld_info.exports]
    macho.shift(shift)
    new_exports_addrs = [e.address for e in dyld_info.exports]
    assert new_exports_addrs == expected_exports_addrs


def test_chained_exports_after_shift():
    bin_path = Path(get_sample("MachO/MachO64_AArch64_weak-sym-fc.bin"))
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    macho = fat.at(0)
    assert macho is not None
    dyld_exports_trie = macho.dyld_exports_trie
    assert dyld_exports_trie is not None

    shift = 0x10000
    loadcommands_end = (
        32 + macho.header.sizeof_cmds
    )  # sizeof(mach_header_64) + size of load command table

    def get_shifted_export(e):
        address = e.address
        if address > loadcommands_end:
            address += shift
        return address

    expected_exports_addrs = [get_shifted_export(e) for e in dyld_exports_trie.exports]
    macho.shift(shift)
    new_exports_addrs = [e.address for e in dyld_exports_trie.exports]
    assert new_exports_addrs == expected_exports_addrs
