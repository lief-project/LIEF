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
    func.add_parameter("A", cu.create_void_type().pointer_to())
    func.add_parameter("B", cu.create_base_type(
        "base_ty", "8", lief.dwarf.editor.BaseType.ENCODING.BOOLEAN
    ).pointer_to())
    struct = cu.create_structure("my_struct_t")
    struct.add_member("next", struct.pointer_to())
    struct.add_member("prev", struct.pointer_to(), 8)
    struct.set_size(2 * 8)
    func.add_parameter("C", struct.pointer_to().pointer_to())
    func.add_parameter("D", cu.create_structure(
        "union_t", lief.dwarf.editor.StructType.TYPE.UNION
    ).pointer_to())
    func.add_parameter("E", cu.create_structure(
        "class_t", lief.dwarf.editor.StructType.TYPE.CLASS
    ).pointer_to())
    func_ty = cu.create_function_type("my_func_t")
    func_ty.add_parameter(cu.create_void_type().pointer_to())
    func_ty.set_return_type(cu.create_void_type().pointer_to())
    func.add_parameter("F",
        cu.create_typedef("my_func_typedef_t", func_ty.pointer_to())
    )
    func.add_parameter(
        "G", cu.create_array(
            "my_array_t", cu.create_void_type().pointer_to(), 10
        ).pointer_to()
    )
    enum = cu.create_enum("my_enum")
    enum.set_size(8)
    enum.add_value("A", 0)
    func.set_return_type(enum.pointer_to())
    func.add_lexical_block(0x1, 0x2)
    var = func.create_stack_variable("my_local_var")
    var.set_stack_offset(8)
    var.set_type(cu.create_void_type().pointer_to())

    func = cu.create_function("test_func_4")
    func.set_external()

    ty = cu.create_generic_type("generic_type")
    func.set_return_type(ty)

    var = cu.create_variable("g_var")
    var.set_addr(0x400)

    output = tmp_path / "simple.dwarf"
    editor.write(output.as_posix())


def test_register_param(tmp_path: Path):
    elf = lief.ELF.parse(get_sample("ELF/ELF64_x86-64_binary_hello-cpp.bin"))
    editor = lief.dwarf.Editor.from_binary(elf)
    cu = editor.create_compilation_unit()
    cu.set_producer("LIEF TEST")

    func = cu.create_function("test_func_1")
    func.set_address(0x1000)
    param = func.add_parameter("arg0", cu.create_void_type().pointer_to())
    param.assign_register("r15")

    output = tmp_path / "reg.dwarf"
    editor.write(output.as_posix())

    dbg = lief.dwarf.load(output)
    func = dbg.find_function("test_func_1")
    assert func.parameters[0].location.id == 15
