"""
Test the DWARF editor interface which allows us to create DWARF files
"""
import lief
import pytest
from utils import get_sample
from pathlib import Path

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

def test_simple(tmp_path: Path):
    elf = lief.ELF.parse(get_sample("ELF/ELF64_x86-64_binary_hello-cpp.bin"))
    editor = lief.dwarf.Editor.from_binary(elf)
    cu = editor.create_compilation_unit()
    cu.set_producer("LIEF TEST")

    func = cu.create_function("test_func_1")
    func.set_address(0x123)

    func = cu.create_function("test_func_2")
    func.set_low_high(0x123, 0x456)

    func = cu.create_function("test_func_3")
    func.set_ranges([
        lief.dwarf.editor.Function.range_t(0x1, 0x2),
        lief.dwarf.editor.Function.range_t(0x3, 0x4),
    ])

    func = cu.create_function("test_func_4")
    func.set_external()

    ty = cu.create_generic_type("generic_type")
    func.set_return_type(ty)

    output = tmp_path / "simple.dwarf"
    editor.write(output.as_posix())
