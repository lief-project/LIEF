from textwrap import dedent
from typing import cast

import lief
import pytest
from utils import get_debug_info, normalize_path, parse_elf, parse_macho

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)


def test_vars_1():
    elf = parse_elf("DWARF/vars_1.elf")
    dbg_info = get_debug_info(elf)
    assert isinstance(dbg_info, lief.dwarf.DebugInfo)

    units = list(dbg_info.compilation_units)
    assert len(units) == 1

    cu = units[0]
    assert cu is not None

    main = cu.find_function("main")
    assert main is not None
    main_ret_type = main.type
    assert isinstance(main_ret_type, lief.dwarf.types.Base)
    assert main_ret_type.name == "int"
    assert main_ret_type.size == 4
    assert main_ret_type.to_decl() == "int"
    assert main_ret_type.encoding == lief.dwarf.types.Base.ENCODING.SIGNED

    types = list(cu.types)
    assert len(types) == 918

    pointers = [
        ty for ty in types if ty is not None and ty.kind == lief.dwarf.Type.KIND.POINTER
    ]
    assert len(pointers) == 142

    # Pointer type
    ptr_type = cast(lief.dwarf.types.Pointer, pointers[1])
    assert ptr_type.kind == lief.dwarf.Type.KIND.POINTER
    assert isinstance(ptr_type, lief.dwarf.types.Pointer)

    underlying_ptr_type = ptr_type.underlying_type
    assert isinstance(underlying_ptr_type, lief.dwarf.types.Base)
    assert ptr_type.name is None
    assert ptr_type.size == 8
    assert ptr_type.to_decl() == "signed char *"

    assert underlying_ptr_type.name == "char"
    assert underlying_ptr_type.size == 1
    assert underlying_ptr_type.encoding == lief.dwarf.types.Base.ENCODING.SIGNED_CHAR

    # Struct type
    structs = [
        ty for ty in types if ty is not None and ty.kind == lief.dwarf.Type.KIND.STRUCT
    ]
    assert len(structs) == 125

    struct_type = cast(lief.dwarf.types.Structure, structs[120])
    assert struct_type.kind == lief.dwarf.Type.KIND.STRUCT
    assert isinstance(struct_type, lief.dwarf.types.Structure)
    assert struct_type.name == "tm"
    assert struct_type.size == 56
    assert (
        normalize_path(struct_type.location.file)
        == "/usr/include/x86_64-linux-gnu/bits/types/struct_tm.h"
    )
    assert struct_type.location.line == 7
    assert struct_type.to_decl() == dedent("""\
    struct tm {
        int tm_sec;
        int tm_min;
        int tm_hour;
        int tm_mday;
        int tm_mon;
        int tm_year;
        int tm_wday;
        int tm_yday;
        int tm_isdst;
        char __padding9__[4];
        long long tm_gmtoff;
        const signed char *tm_zone;
    }""")

    members = struct_type.members
    assert len(members) == 11

    assert members[0].name == "tm_sec"
    assert members[0].offset == 0
    assert members[0].type is not None
    assert members[0].type.kind == lief.dwarf.Type.KIND.BASE

    assert members[1].name == "tm_min"
    assert members[1].offset == 4
    assert members[1].type is not None
    assert members[1].type.kind == lief.dwarf.Type.KIND.BASE

    assert members[2].name == "tm_hour"
    assert members[2].offset == 8
    assert members[2].type is not None
    assert members[2].type.kind == lief.dwarf.Type.KIND.BASE

    assert members[3].name == "tm_mday"
    assert members[3].offset == 12
    assert members[3].type is not None
    assert members[3].type.kind == lief.dwarf.Type.KIND.BASE

    assert members[4].name == "tm_mon"
    assert members[4].offset == 16
    assert members[4].type is not None
    assert members[4].type.kind == lief.dwarf.Type.KIND.BASE

    assert members[10].name == "tm_zone"
    assert members[10].offset == 48

    m10_type = members[10].type
    assert isinstance(m10_type, lief.dwarf.types.Pointer)
    m10_ut = m10_type.underlying_type
    assert isinstance(m10_ut, lief.dwarf.types.Const)
    assert isinstance(m10_ut.underlying_type, lief.dwarf.types.Base)

    # Array type
    arrays = [
        ty for ty in types if ty is not None and ty.kind == lief.dwarf.Type.KIND.ARRAY
    ]
    assert len(arrays) == 6

    array_type = cast(lief.dwarf.types.Array, arrays[5])
    assert array_type.kind == lief.dwarf.Type.KIND.ARRAY
    assert array_type.name is None
    assert array_type.size == 40
    assert array_type.to_decl() == "unsigned char[40]"
    assert isinstance(array_type, lief.dwarf.types.Array)

    underlying_array_type = array_type.underlying_type
    assert isinstance(underlying_array_type, lief.dwarf.types.Base)

    # Const type

    consts = [
        ty
        for ty in types
        if ty is not None and ty.kind == lief.dwarf.Type.KIND.CONST_KIND
    ]
    assert len(consts) == 141

    cst_type = cast(lief.dwarf.types.Pointer, consts[137])
    assert cst_type.kind == lief.dwarf.Type.KIND.CONST_KIND
    assert (
        cst_type.to_decl()
        == "class new_allocator<std::__detail::_Hash_node_base*> *const"
    )
    assert isinstance(cst_type, lief.dwarf.types.Const)

    underlying_cst_type = cst_type.underlying_type
    assert isinstance(underlying_cst_type, lief.dwarf.types.Pointer)
    inner_cst_type = underlying_cst_type.underlying_type
    assert inner_cst_type is not None
    assert inner_cst_type.kind == lief.dwarf.Type.KIND.CLASS
    assert inner_cst_type.name == "new_allocator<std::__detail::_Hash_node_base*>"


def test_lief():
    macho = parse_macho("private/DWARF/libLIEF.dylib").at(0)
    assert macho is not None

    dbg_info = get_debug_info(macho)
    assert dbg_info is not None


def test_bitfield():
    elf = parse_elf("private/DWARF/libLIEF.so")

    dbg_info = get_debug_info(elf)
    assert dbg_info is not None

    float_specs = cast(lief.dwarf.types.ClassLike, dbg_info.find_type("float_specs"))

    members = list(float_specs.members)
    assert len(members) == 7

    assert members[0].offset == 0
    assert members[0].bit_offset == 0

    assert members[1].offset == 4
    assert members[1].bit_offset == 32

    assert members[2].offset == 5
    assert members[2].bit_offset == 40


def test_DW_TAG_reference_type():
    elf = parse_elf("private/DWARF/types/DW_TAG_reference_type.o")

    dbg_info = get_debug_info(elf)
    assert dbg_info is not None

    F = dbg_info.find_function("_Z3foov")
    assert F is not None

    ref = cast(lief.dwarf.types.Reference, F.type)
    assert isinstance(ref, lief.dwarf.types.Reference)

    assert ref.underlying_type is not None
    assert ref.underlying_type.name == "int"
    assert ref.to_decl() == "int &&"


def test_DW_TAG_atomic_type():
    elf = parse_elf("private/DWARF/types/DW_TAG_atomic_type.o")

    dbg_info = get_debug_info(elf)
    assert dbg_info is not None

    V = dbg_info.find_variable("i")
    assert V is not None

    v_type = V.type
    assert v_type is not None
    atomic = cast(
        lief.dwarf.types.Atomic, cast(lief.dwarf.types.Typedef, v_type).underlying_type
    )
    assert isinstance(atomic, lief.dwarf.types.Atomic)

    assert atomic.underlying_type is not None
    assert atomic.underlying_type.name == "int"
    assert atomic.to_decl() == "<unknown type>"


def test_DW_TAG_template_alias():
    elf = parse_elf("private/DWARF/types/DW_TAG_template_alias.o")

    dbg_info = get_debug_info(elf)
    assert dbg_info is not None

    V = dbg_info.find_variable("a")
    assert V is not None

    template_alias = cast(lief.dwarf.types.TemplateAlias, V.type)
    assert template_alias.to_decl() == "<unknown type>"
    assert isinstance(template_alias, lief.dwarf.types.TemplateAlias)

    assert template_alias.name == "A"

    params = template_alias.parameters
    assert len(params) == 2

    assert isinstance(params[0], lief.dwarf.parameters.TemplateType)
    assert params[0].name == "B"
    assert params[0].type is not None
    assert params[0].type.name == "int"

    assert isinstance(params[1], lief.dwarf.parameters.TemplateValue)
    assert params[1].name == "C"
    assert params[1].type is not None
    assert params[1].type.name == "int"


def test_DW_TAG_ptr_to_member_type():
    elf = parse_elf("private/DWARF/types/DW_TAG_ptr_to_member_type.o")

    dbg_info = get_debug_info(elf)
    assert dbg_info is not None

    V = dbg_info.find_variable("x")
    assert V is not None

    ptr_member = cast(lief.dwarf.types.PointerToMember, V.type)
    assert isinstance(ptr_member, lief.dwarf.types.PointerToMember)
    assert ptr_member.underlying_type is not None
    assert ptr_member.underlying_type.name == "int"
    assert ptr_member.containing_type is not None
    assert ptr_member.containing_type.name == "S"
    assert ptr_member.to_decl() == "<unknown type>"
    assert isinstance(ptr_member.containing_type, lief.dwarf.types.Structure)


def test_DW_TAG_set_type():
    elf = parse_elf("private/DWARF/types/DW_TAG_set_type.o")

    dbg_info = get_debug_info(elf)
    assert dbg_info is not None

    CU = list(dbg_info.compilation_units)[0]
    assert CU is not None
    assert CU.language.lang == lief.dwarf.CompilationUnit.Language.LANG.MODULA
    assert CU.language.version == 3

    set_type = cast(lief.dwarf.types.SetTy, dbg_info.find_type("ST"))
    assert isinstance(set_type, lief.dwarf.types.SetTy)

    assert set_type.to_decl() == "<unknown type>"
    set_ut = set_type.underlying_type
    assert isinstance(set_ut, lief.dwarf.types.Enum)
    assert set_ut.name == "Enum"


def test_DW_TAG_rvalue_reference_type():
    elf = parse_elf("private/DWARF/types/DW_TAG_rvalue_reference_type.o")

    dbg_info = get_debug_info(elf)
    assert dbg_info is not None

    ty = cast(lief.dwarf.types.Class, dbg_info.find_type("deleted"))

    functions: list[lief.dwarf.Function] = [f for f in ty.functions if f is not None]
    assert len(functions) == 8

    deleted = [
        f for f in functions if f.name == "deleted" and f.debug_location.line == 8
    ]

    assert len(deleted)

    parameters = deleted[0].parameters
    assert len(parameters) == 2

    assert parameters[1] is not None
    param_1_type = parameters[1].type
    assert param_1_type is not None
    rval_ref = cast(lief.dwarf.types.RValueReference, param_1_type)
    assert isinstance(rval_ref, lief.dwarf.types.RValueReference)
    assert rval_ref.to_decl() == "<unknown type>"
    assert rval_ref.underlying_type is not None
    assert rval_ref.underlying_type.name == "deleted"


def test_DW_TAG_immutable_type():
    elf = parse_elf("private/DWARF/types/DW_TAG_immutable_type.o")

    dbg_info = get_debug_info(elf)
    assert dbg_info is not None

    CU = list(dbg_info.compilation_units)[0]
    assert CU is not None
    assert CU.language.lang == lief.dwarf.CompilationUnit.Language.LANG.D
    assert CU.language.version == 0

    V = dbg_info.find_variable("a")
    assert V is not None

    imm = cast(lief.dwarf.types.Immutable, V.type)

    assert isinstance(imm, lief.dwarf.types.Immutable)
    assert imm.to_decl() == "<unknown type>"
    assert imm.underlying_type is not None
    assert imm.underlying_type.name == "char"


def test_DW_TAG_subroutine_type():
    elf = parse_elf("private/DWARF/types/DW_TAG_subroutine_type.o")

    dbg_info = get_debug_info(elf)
    assert dbg_info is not None

    V = dbg_info.find_variable("y")
    assert V is not None

    ptr_member = cast(lief.dwarf.types.PointerToMember, V.type)
    assert ptr_member.to_decl() == "<unknown type>"

    subroutine_ty = cast(lief.dwarf.types.Subroutine, ptr_member.underlying_type)
    assert isinstance(subroutine_ty, lief.dwarf.types.Subroutine)
    params = subroutine_ty.parameters
    assert len(params) == 2

    assert params[0] is not None
    p0_type = params[0].type
    assert p0_type is not None
    p0_underlying = cast(lief.dwarf.types.Pointer, p0_type).underlying_type
    assert p0_underlying is not None
    assert p0_underlying.name == "S"
    assert params[1] is not None
    p1_type = params[1].type
    assert p1_type is not None
    assert p1_type.name == "int"


def test_DW_TAG_enumeration_type():
    elf = parse_elf("private/DWARF/types/DW_TAG_enumeration_type.o")

    dbg_info = get_debug_info(elf)
    assert dbg_info is not None

    enum = cast(lief.dwarf.types.Enum, dbg_info.find_type("Enum"))

    assert isinstance(enum, lief.dwarf.types.Enum)
    entry = enum.find_entry(4)
    assert entry is not None
    assert entry.name == "epsilon"

    assert enum.to_decl() == dedent("""\
    enum Enum {
        alpha = 0i8,
        beta = 1i8,
        gamma = 2i8,
        delta = 3i8,
        epsilon = 4i8,
        theta = 5i8,
        psi = 6i8,
        zeta = 7i8
    }""")
    loc = enum.location

    assert normalize_path(loc.file) == "/home/cm3/settest/src/Main.m3"
    assert loc.line == 11

    entries = enum.entries

    assert len(entries) == 8

    assert entries[0].name == "alpha"
    assert entries[0].value == 0


def test_DW_TAG_string_type_cobol():
    elf = parse_elf("private/DWARF/cobol_hello.o")

    dbg_info = get_debug_info(elf)
    assert dbg_info is not None

    CU = cast(lief.dwarf.CompilationUnit, next(dbg_info.compilation_units))

    lang = CU.language

    assert lang.lang == lief.dwarf.CompilationUnit.Language.LANG.COBOL
    assert lang.version == 1985

    string_ty = dbg_info.find_type("X(10)")
    assert isinstance(string_ty, lief.dwarf.types.StringTy)


def test_DW_TAG_string_type_fortran():
    elf = parse_elf("private/DWARF/types/DW_TAG_string_type.o")

    dbg_info = get_debug_info(elf)
    assert dbg_info is not None

    CU = cast(lief.dwarf.CompilationUnit, next(dbg_info.compilation_units))

    lang = CU.language

    assert lang.lang == lief.dwarf.CompilationUnit.Language.LANG.FORTRAN
    assert lang.version == 1995

    string_ty = dbg_info.find_type("CHARACTER_2")
    assert isinstance(string_ty, lief.dwarf.types.StringTy)
    assert string_ty.size == 8


def test_DW_TAG_volatile_type():
    elf = parse_elf("private/DWARF/types/DW_TAG_volatile_type.o")

    dbg_info = get_debug_info(elf)
    assert dbg_info is not None

    V = dbg_info.find_variable("sink")
    assert V is not None

    volatile = cast(lief.dwarf.types.Volatile, V.type)
    assert isinstance(volatile, lief.dwarf.types.Volatile)

    assert volatile.underlying_type is not None
    assert volatile.underlying_type.name == "int"


def test_DW_TAG_restrict_type():
    elf = parse_elf("private/DWARF/types/DW_TAG_restrict_type.o")

    dbg_info = get_debug_info(elf)
    assert dbg_info is not None

    F = dbg_info.find_function("foo")
    assert F is not None
    params = F.parameters
    assert len(params) == 2

    assert params[1] is not None
    p1_type = params[1].type
    assert p1_type is not None
    restrict = cast(
        lief.dwarf.types.Restrict,
        cast(lief.dwarf.types.Pointer, p1_type).underlying_type,
    )
    assert isinstance(restrict, lief.dwarf.types.Restrict)

    restrict_ut = restrict.underlying_type
    assert restrict_ut is not None
    restrict_ut_inner = cast(lief.dwarf.types.Pointer, restrict_ut).underlying_type
    assert restrict_ut_inner is not None
    assert restrict_ut_inner.name == "double"


def test_DW_TAG_reference_type_alt():
    elf = parse_elf("private/DWARF/types/DW_TAG_reference_type.o")

    dbg_info = get_debug_info(elf)
    assert dbg_info is not None

    F = dbg_info.find_function("foo")
    assert F is not None
    ret = cast(lief.dwarf.types.Reference, F.type)

    assert isinstance(ret, lief.dwarf.types.Reference)

    assert ret.underlying_type is not None
    assert ret.underlying_type.name == "int"


def test_DW_TAG_subrange_type():
    elf = parse_elf("private/DWARF/types/DW_TAG_subrange_type.o")

    dbg_info = get_debug_info(elf)
    assert dbg_info is not None

    V = dbg_info.find_variable("elemnt")
    assert V is not None
    array = cast(lief.dwarf.types.Array, V.type)

    size_info = array.size_info

    assert size_info.size == 1
    assert size_info.name == ""
    assert size_info.type is not None
    assert size_info.type.name == "__ARRAY_SIZE_TYPE__"

    assert array.underlying_type is not None
    assert array.underlying_type.name == "CHARACTER_2"


def test_DW_TAG_thrown_type():
    elf = parse_elf("private/DWARF/types/DW_TAG_thrown_type.o")

    dbg_info = get_debug_info(elf)
    assert dbg_info is not None

    CU = next(dbg_info.compilation_units)
    assert CU is not None

    lang = CU.language

    assert lang.lang == lief.dwarf.CompilationUnit.Language.LANG.SWIFT
    F = dbg_info.find_function("f")
    assert F is not None

    thrown_types = F.thrown_types
    assert len(thrown_types) == 2

    assert isinstance(thrown_types[0], lief.dwarf.types.Thrown)
    assert thrown_types[0].underlying_type is not None
    assert thrown_types[0].underlying_type.name == "Error"

    assert isinstance(thrown_types[1], lief.dwarf.types.Thrown)
    assert thrown_types[1].underlying_type is not None
    assert thrown_types[1].underlying_type.name == "DifferentError"


def test_DW_TAG_packed_type():
    elf = parse_elf("private/DWARF/types/DW_TAG_packed_type.ps.o")

    dbg_info = get_debug_info(elf)
    assert dbg_info is not None

    packed = cast(lief.dwarf.types.Packed, dbg_info.find_type("TFILEINFO"))
    assert isinstance(packed, lief.dwarf.types.Packed)

    member = packed.members
    assert len(member) == 10

    assert member[5].offset == 10


def test_DW_TAG_shared_type():
    elf = parse_elf("private/DWARF/D_test.bin")

    dbg_info = get_debug_info(elf)
    assert dbg_info is not None

    CU = next(dbg_info.compilation_units)
    assert CU is not None

    lang = CU.language

    assert lang.lang == lief.dwarf.CompilationUnit.Language.LANG.D

    V = dbg_info.find_variable("test.flag")
    assert V is not None

    shared = cast(lief.dwarf.types.Shared, V.type)
    assert isinstance(shared, lief.dwarf.types.Shared)
    assert shared.underlying_type is not None
    assert shared.underlying_type.name == "int"


def test_DW_TAG_interface_type():
    elf = parse_elf("private/DWARF/java_Pig.o")

    dbg_info = get_debug_info(elf)
    assert dbg_info is not None

    CU = next(dbg_info.compilation_units)
    assert CU is not None

    lang = CU.language

    assert lang.lang == lief.dwarf.CompilationUnit.Language.LANG.JAVA

    V = dbg_info.find_variable("_CD_Pig")
    assert V is not None

    array = cast(lief.dwarf.types.Array, V.type)
    assert isinstance(array, lief.dwarf.types.Array)
    assert array.size_info.type is not None
    assert array.size_info.type.name == "sizetype"
    assert array.size_info.size == 3

    interface = cast(lief.dwarf.types.Interface, dbg_info.find_type("Animal"))
    assert isinstance(interface, lief.dwarf.types.Interface)
