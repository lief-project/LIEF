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


def test_qualifiers(tmp_path: Path):
    elf = parse_elf("ELF/ELF64_x86-64_binary_hello-cpp.bin")
    editor = lief.dwarf.Editor.from_binary(elf)
    assert editor is not None
    cu = editor.create_compilation_unit()
    assert cu is not None

    int_t = cu.create_base_type("int", 4, lief.dwarf.editor.BaseType.ENCODING.SIGNED)
    assert int_t is not None

    const_int = cu.create_const_type(int_t)
    volatile_int = cu.create_volatile_type(int_t)
    assert const_int is not None
    assert volatile_int is not None
    cv_int = cu.create_volatile_type(const_int)
    assert cv_int is not None

    # Qualifying the same type again must not create a new DIE
    const_int_2 = cu.create_const_type(int_t)
    assert const_int_2 is not None

    for name, addr, ty in (
        ("c_var", 0x1000, const_int),
        ("c_var_2", 0x1018, const_int_2),
        ("v_var", 0x1004, volatile_int),
        ("cv_var", 0x1008, cv_int),
        ("ptr_c_var", 0x1010, cast(lief.dwarf.editor.Type, const_int.pointer_to())),
    ):
        var = cu.create_variable(name)
        assert var is not None
        var.set_addr(addr)
        var.set_type(ty)

    output = tmp_path / "qualifiers.dwarf"
    editor.write(output.as_posix())

    dbg = lief.dwarf.load(output.as_posix())
    assert dbg is not None

    def var_type(name: str) -> lief.dwarf.Type:
        var = dbg.find_variable(name)
        assert var is not None
        assert var.type is not None
        return var.type

    c_ty = var_type("c_var")
    assert isinstance(c_ty, lief.dwarf.types.Const)
    assert c_ty.underlying_type is not None
    assert c_ty.underlying_type.name == "int"

    v_ty = var_type("v_var")
    assert isinstance(v_ty, lief.dwarf.types.Volatile)
    assert v_ty.underlying_type is not None
    assert v_ty.underlying_type.name == "int"

    cv_ty = var_type("cv_var")
    assert isinstance(cv_ty, lief.dwarf.types.Volatile)
    inner = cv_ty.underlying_type
    assert isinstance(inner, lief.dwarf.types.Const)
    assert inner.underlying_type is not None
    assert inner.underlying_type.name == "int"

    ptr_ty = var_type("ptr_c_var")
    assert isinstance(ptr_ty, lief.dwarf.types.Pointer)
    assert isinstance(ptr_ty.underlying_type, lief.dwarf.types.Const)

    c_ty_2 = var_type("c_var_2")
    assert isinstance(c_ty_2, lief.dwarf.types.Const)

    # Qualifying the same type twice reuses the same DW_TAG_const_type entry:
    # the output must hold a single DIE per qualified type.
    cu_out = next(iter(dbg.compilation_units))
    assert cu_out is not None
    tags = [ty.kind for ty in cu_out.types if ty is not None]
    assert tags.count(lief.dwarf.Type.KIND.CONST_KIND) == 1
    assert tags.count(lief.dwarf.Type.KIND.VOLATILE) == 2
