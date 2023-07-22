#!/usr/bin/env python
# -*- coding: utf-8 -*-

import lief
import pytest

from utils import get_sample


@pytest.mark.parametrize("test_exe", [
    "PE/PE32_x86_binary_HelloWorld.exe",
    "PE/PE64_x86-64_binary_HelloWorld.exe",
])
def test_add_ordinal(tmp_path, test_exe):
    lib_name = "LIEF_UNITTEST.dll"
    ordinal_val = 42
    orig_path = get_sample(test_exe)
    new_path = tmp_path / "add_ordinal.exe"

    binary = lief.parse(orig_path)
    pe_type = binary.optional_header.magic
    ordinal_mask = 0x1 << 63  # PE32+, aka 64-bit PE
    if pe_type == lief.PE.PE_TYPE.PE32:
        ordinal_mask = 0x1 << 31  # PE32, aka 32-bit PE
    test_lib = binary.add_library(lib_name)
    ord_data = ordinal_val | ordinal_mask
    new_entry = lief.PE.ImportEntry(data=ord_data, type=pe_type)
    test_lib.add_entry(entry=new_entry)

    builder = lief.PE.Builder(binary)
    builder.build_imports(True).patch_imports(True)
    builder.build()
    builder.write(new_path.as_posix())

    new_binary = lief.parse(new_path.as_posix())
    assert new_binary.has_import(lib_name)
    new_lib = binary.get_import(lib_name)
    first_ord = next(iter([e for e in new_lib.entries if e.is_ordinal]))
    assert first_ord is not None
    assert first_ord.ordinal == ordinal_val


def test_resolve_ordinal():
    pe = lief.PE.parse(get_sample("PE/PE64_x86-64_binary_mfc-application.exe"))
    imp = pe.get_import("OLEAUT32.dll")
    new_imp: lief.PE.Import = lief.PE.resolve_ordinals(imp)
    assert new_imp.entries[0].name == "SysAllocString"
    assert new_imp.entries[1].name == "VariantClear"
