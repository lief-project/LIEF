"""
Test the DWARF editor interface which allows us to create DWARF files
"""

from pathlib import Path
from typing import cast

import lief
import pytest
from utils import parse_elf

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)


def test_simple(tmp_path: Path):
    elf = parse_elf("ELF/ELF64_x86-64_binary_hello-cpp.bin")
    editor = lief.dwarf.Editor.from_binary(elf)
    assert editor is not None
    cu = editor.create_compilation_unit()
    assert cu is not None
    cu.set_producer("LIEF TEST")

    func = cu.create_function("test_func_1")
    assert func is not None
    func.set_address(0x123)

    func = cu.create_function("test_func_2")
    assert func is not None
    func.set_low_high(0x123, 0x456)

    func = cu.create_function("test_func_3")
    assert func is not None
    func.set_ranges(
        [
            lief.dwarf.editor.Function.range_t(0x1, 0x2),
            lief.dwarf.editor.Function.range_t(0x3, 0x4),
        ]
    )
    void_type = cu.create_void_type()
    assert void_type is not None
    func.add_parameter("A", cast(lief.dwarf.editor.Type, void_type.pointer_to()))

    base_type = cu.create_base_type(
        "base_ty", 8, lief.dwarf.editor.BaseType.ENCODING.BOOLEAN
    )
    assert base_type is not None
    func.add_parameter("B", cast(lief.dwarf.editor.Type, base_type.pointer_to()))

    struct = cu.create_structure("my_struct_t")
    assert struct is not None
    struct.add_member("next", cast(lief.dwarf.editor.Type, struct.pointer_to()))
    struct.add_member("prev", cast(lief.dwarf.editor.Type, struct.pointer_to()), 8)
    struct.set_size(2 * 8)
    func.add_parameter(
        "C",
        cast(
            lief.dwarf.editor.Type,
            cast(lief.dwarf.editor.PointerType, struct.pointer_to()).pointer_to(),
        ),
    )

    union_t = cu.create_structure("union_t", lief.dwarf.editor.StructType.TYPE.UNION)
    assert union_t is not None
    func.add_parameter("D", cast(lief.dwarf.editor.Type, union_t.pointer_to()))

    class_t = cu.create_structure("class_t", lief.dwarf.editor.StructType.TYPE.CLASS)
    assert class_t is not None
    func.add_parameter("E", cast(lief.dwarf.editor.Type, class_t.pointer_to()))

    func_ty = cu.create_function_type("my_func_t")
    assert func_ty is not None
    func_ty.add_parameter(cast(lief.dwarf.editor.Type, void_type.pointer_to()))
    func_ty.set_return_type(cast(lief.dwarf.editor.Type, void_type.pointer_to()))
    func.add_parameter(
        "F",
        cast(
            lief.dwarf.editor.Type,
            cu.create_typedef(
                "my_func_typedef_t", cast(lief.dwarf.editor.Type, func_ty.pointer_to())
            ),
        ),
    )
    array_t = cu.create_array(
        "my_array_t", cast(lief.dwarf.editor.Type, void_type.pointer_to()), 10
    )
    assert array_t is not None
    func.add_parameter("G", cast(lief.dwarf.editor.Type, array_t.pointer_to()))
    enum = cu.create_enum("my_enum")
    assert enum is not None
    enum.set_size(8)
    enum.add_value("A", 0)
    func.set_return_type(cast(lief.dwarf.editor.Type, enum.pointer_to()))
    func.add_lexical_block(0x1, 0x2)
    var = func.create_stack_variable("my_local_var")
    assert var is not None
    var.set_stack_offset(8)
    var.set_type(cast(lief.dwarf.editor.Type, void_type.pointer_to()))

    func = cu.create_function("test_func_4")
    assert func is not None
    func.set_external()

    ty = cu.create_generic_type("generic_type")
    assert ty is not None
    func.set_return_type(ty)

    var = cu.create_variable("g_var")
    assert var is not None
    var.set_addr(0x400)

    output = tmp_path / "simple.dwarf"
    editor.write(output.as_posix())


def test_register_param(tmp_path: Path):
    elf = parse_elf("ELF/ELF64_x86-64_binary_hello-cpp.bin")
    editor = lief.dwarf.Editor.from_binary(elf)
    assert editor is not None
    cu = editor.create_compilation_unit()
    assert cu is not None
    cu.set_producer("LIEF TEST")

    func = cu.create_function("test_func_1")
    assert func is not None
    func.set_address(0x1000)
    void_type = cu.create_void_type()
    assert void_type is not None
    param = func.add_parameter(
        "arg0", cast(lief.dwarf.editor.Type, void_type.pointer_to())
    )
    assert param is not None
    param.assign_register("r15")

    output = tmp_path / "reg.dwarf"
    editor.write(output.as_posix())

    dbg = lief.dwarf.load(output.as_posix())
    assert dbg is not None
    func = dbg.find_function("test_func_1")
    assert func is not None
    param = func.parameters[0]
    assert param is not None
    loc = param.location
    assert loc is not None
    assert isinstance(loc, lief.dwarf.Parameter.RegisterLoc)
    assert loc.id == 15
