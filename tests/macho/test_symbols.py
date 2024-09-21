#!/usr/bin/env python
import pytest
import lief
import pathlib
import re
from utils import is_osx, get_sample

from .test_builder import run_program

def test_unexport(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_sym2remove.bin"))
    original = lief.parse(bin_path.as_posix())
    output = f"{tmp_path}/{bin_path.name}"
    exported = {s.name for s in original.symbols if s.has_export_info}

    assert "_remove_me" in exported

    original.unexport("_remove_me")

    original.write(output)
    new = lief.parse(output)

    exported = {s.name for s in new.symbols if s.has_export_info}
    assert "_remove_me" not in exported

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_osx():
        assert run_program(bin_path.as_posix())
        stdout = run_program(output)

        print(stdout)
        assert re.search(r'Hello World', stdout) is not None


def test_rm_symbols(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_sym2remove.bin"))
    original = lief.parse(bin_path.as_posix())
    output = f"{tmp_path}/{bin_path.name}"

    for s in ["__ZL6BANNER", "_remove_me"]:
        assert original.can_remove_symbol(s)
        original.remove_symbol(s)


    original.write(output)
    new = lief.parse(output)

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    assert new.get_symbol("__ZL6BANNER") is None
    assert new.get_symbol("_remove_me") is None

    if is_osx():
        assert run_program(bin_path.as_posix())
        stdout = run_program(output)

        print(stdout)
        assert re.search(r'Hello World', stdout) is not None

def test_dynsym_command():
    macho = lief.MachO.parse(get_sample("MachO/MachO64_x86-64_binary_all.bin")).at(0)

    dynsym = macho.dynamic_symbol_command

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
        print(sym)

    indirect_symbols = dynsym.indirect_symbols
    assert len(indirect_symbols) == 4

    assert indirect_symbols[0].name == "_printf"
    assert indirect_symbols[1].name == "dyld_stub_binder"

    assert indirect_symbols[2].name == ""
    assert indirect_symbols[2].category == lief.MachO.Symbol.CATEGORY.INDIRECT_ABS

    assert indirect_symbols[3].name == "_printf"

def test_symbol_library():
    macho = lief.MachO.parse(get_sample("MachO/macho-arm64-osx-vtable-chained-fixups.bin")).at(0)
    symbols = macho.symbols
    assert len(symbols) == 16

    bindings = list(macho.bindings)
    assert len(bindings) == 3

    assert bindings[0].symbol.name == "_printf"
    assert bindings[0].symbol.is_external
    assert bindings[0].symbol.library.name == "/usr/lib/libSystem.B.dylib"
    assert bindings[0].symbol.library_ordinal == 2

    assert bindings[1].symbol.is_external
    assert bindings[1].symbol.name == "__ZTVN10__cxxabiv117__class_type_infoE"
    assert bindings[1].symbol.library.name == "/usr/lib/libc++.1.dylib"
    assert bindings[1].symbol.library_ordinal == 1

    assert bindings[2].symbol.is_external
    assert bindings[2].symbol.name == "__ZTVN10__cxxabiv120__si_class_type_infoE"
    assert bindings[2].symbol.library.name == "/usr/lib/libc++.1.dylib"
    assert bindings[2].symbol.library_ordinal == 1

@pytest.mark.skipif(not lief.__extended__, reason="needs LIEF extended")
def test_demangling():
    macho = lief.MachO.parse(get_sample("MachO/FAT_MachO_x86_x86-64_library_libc++abi.dylib")).at(0)

    assert macho.symbols[1].demangled_name == "void __cxxabiv1::(anonymous namespace)::demangle<__cxxabiv1::(anonymous namespace)::Db>(char const*, char const*, __cxxabiv1::(anonymous namespace)::Db&, int&)"
    assert macho.symbols[486].demangled_name == "___cxa_deleted_virtual"
