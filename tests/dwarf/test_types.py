import lief
import pytest
from utils import get_sample, normalize_path

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

def test_vars_1():
    elf = lief.ELF.parse(get_sample("DWARF/vars_1.elf"))
    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert isinstance(dbg_info, lief.dwarf.DebugInfo)

    units = list(dbg_info.compilation_units)
    assert len(units) == 1

    cu = units[0]

    main = cu.find_function("main")
    main_ret_type = main.type
    assert isinstance(main_ret_type, lief.dwarf.types.Base)
    assert main_ret_type.name == "int"
    assert main_ret_type.size == 4
    assert main_ret_type.encoding == lief.dwarf.types.Base.ENCODING.SIGNED

    types = list(cu.types)
    assert len(types) == 918

    pointers = [ty for ty in types if ty.kind == lief.dwarf.Type.KIND.POINTER]
    assert len(pointers) == 142

    # Pointer type
    ptr_type: lief.dwarf.types.Pointer = pointers[1]
    assert ptr_type.kind == lief.dwarf.Type.KIND.POINTER
    assert isinstance(ptr_type, lief.dwarf.types.Pointer)

    underlying_ptr_type = ptr_type.underlying_type
    assert isinstance(underlying_ptr_type, lief.dwarf.types.Base)
    assert ptr_type.name is None
    assert ptr_type.size == 8

    assert underlying_ptr_type.name == "char"
    assert underlying_ptr_type.size == 1
    assert underlying_ptr_type.encoding == lief.dwarf.types.Base.ENCODING.SIGNED_CHAR

    # Struct type
    structs = [ty for ty in types if ty.kind == lief.dwarf.Type.KIND.STRUCT]
    assert len(structs) == 125

    struct_type: lief.dwarf.types.Structure = structs[120]
    assert struct_type.kind == lief.dwarf.Type.KIND.STRUCT
    assert isinstance(struct_type, lief.dwarf.types.Structure)
    assert struct_type.name == "tm"
    assert struct_type.size == 56
    assert normalize_path(struct_type.location.file) == "/usr/include/x86_64-linux-gnu/bits/types/struct_tm.h"
    assert struct_type.location.line == 7

    members = struct_type.members
    assert len(members) == 11

    assert members[0].name == "tm_sec"
    assert members[0].offset == 0
    assert members[0].type.kind == lief.dwarf.Type.KIND.BASE

    assert members[1].name == "tm_min"
    assert members[1].offset == 4
    assert members[1].type.kind == lief.dwarf.Type.KIND.BASE

    assert members[2].name == "tm_hour"
    assert members[2].offset == 8
    assert members[2].type.kind == lief.dwarf.Type.KIND.BASE

    assert members[3].name == "tm_mday"
    assert members[3].offset == 12
    assert members[3].type.kind == lief.dwarf.Type.KIND.BASE

    assert members[4].name == "tm_mon"
    assert members[4].offset == 16
    assert members[4].type.kind == lief.dwarf.Type.KIND.BASE

    assert members[10].name == "tm_zone"
    assert members[10].offset == 48

    assert isinstance(members[10].type, lief.dwarf.types.Pointer)
    assert isinstance(members[10].type.underlying_type, lief.dwarf.types.Const)
    assert isinstance(members[10].type.underlying_type.underlying_type, lief.dwarf.types.Base)

    # Array type
    arrays = [ty for ty in types if ty.kind == lief.dwarf.Type.KIND.ARRAY]
    assert len(arrays) == 6

    array_type: lief.dwarf.types.Array = arrays[5]
    assert array_type.kind == lief.dwarf.Type.KIND.ARRAY
    assert array_type.name is None
    assert array_type.size == 40
    assert isinstance(array_type, lief.dwarf.types.Array)

    underlying_array_type = array_type.underlying_type
    assert isinstance(underlying_array_type, lief.dwarf.types.Base)

    # Const type

    consts = [ty for ty in types if ty.kind == lief.dwarf.Type.KIND.CONST_KIND]
    assert len(consts) == 141

    cst_type: lief.dwarf.types.Pointer = consts[137]
    assert cst_type.kind == lief.dwarf.Type.KIND.CONST_KIND
    assert isinstance(cst_type, lief.dwarf.types.Const)

    underlying_cst_type = cst_type.underlying_type
    assert isinstance(underlying_cst_type, lief.dwarf.types.Pointer)
    assert underlying_cst_type.underlying_type.kind == lief.dwarf.Type.KIND.CLASS
    assert underlying_cst_type.underlying_type.name == "new_allocator<std::__detail::_Hash_node_base*>"

def test_lief():
    macho = lief.MachO.parse(get_sample("private/DWARF/libLIEF.dylib")).at(0)

    dbg_info: lief.dwarf.DebugInfo = macho.debug_info
    assert dbg_info is not None

def test_bitfield():
    elf = lief.ELF.parse(get_sample("private/DWARF/libLIEF.so"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert dbg_info is not None

    float_specs: lief.dwarf.types.ClassLike = dbg_info.find_type("float_specs")

    members = list(float_specs.members)
    assert len(members) == 7

    assert members[0].offset == 0
    assert members[0].bit_offset == 0

    assert members[1].offset == 4
    assert members[1].bit_offset == 32

    assert members[2].offset == 5
    assert members[2].bit_offset == 40


def test_DW_TAG_reference_type():
    elf = lief.ELF.parse(get_sample("private/DWARF/types/DW_TAG_reference_type.o"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert dbg_info is not None

    F = dbg_info.find_function("_Z3foov")

    ref: lief.dwarf.types.Reference = F.type
    assert isinstance(ref, lief.dwarf.types.Reference)

    assert ref.underlying_type.name == "int"


def test_DW_TAG_atomic_type():
    elf = lief.ELF.parse(get_sample("private/DWARF/types/DW_TAG_atomic_type.o"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert dbg_info is not None

    V = dbg_info.find_variable("i")

    atomic: lief.dwarf.types.Atomic = V.type.underlying_type
    assert isinstance(atomic, lief.dwarf.types.Atomic)

    assert atomic.underlying_type.name == "int"

def test_DW_TAG_template_alias():
    elf = lief.ELF.parse(get_sample("private/DWARF/types/DW_TAG_template_alias.o"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert dbg_info is not None

    V = dbg_info.find_variable("a")

    template_alias: lief.dwarf.types.TemplateAlias = V.type
    assert isinstance(template_alias, lief.dwarf.types.TemplateAlias)

    assert template_alias.name == "A"

    params = template_alias.parameters
    assert len(params) == 2

    assert isinstance(params[0], lief.dwarf.parameters.TemplateType)
    assert params[0].name == "B"
    assert params[0].type.name == "int"

    assert isinstance(params[1], lief.dwarf.parameters.TemplateValue)
    assert params[1].name == "C"
    assert params[1].type.name == "int"

def test_DW_TAG_ptr_to_member_type():
    elf = lief.ELF.parse(get_sample("private/DWARF/types/DW_TAG_ptr_to_member_type.o"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert dbg_info is not None

    V = dbg_info.find_variable("x")

    ptr_member: lief.dwarf.types.PointerToMember = V.type
    assert isinstance(ptr_member, lief.dwarf.types.PointerToMember)
    assert ptr_member.underlying_type.name == "int"
    assert ptr_member.containing_type.name == "S"
    assert isinstance(ptr_member.containing_type, lief.dwarf.types.Structure)

def test_DW_TAG_set_type():
    elf = lief.ELF.parse(get_sample("private/DWARF/types/DW_TAG_set_type.o"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert dbg_info is not None

    CU = list(dbg_info.compilation_units)[0]
    assert CU.language.lang == lief.dwarf.CompilationUnit.Language.LANG.MODULA
    assert CU.language.version == 3

    set_type: lief.dwarf.types.SetTy = dbg_info.find_type("ST")
    assert isinstance(set_type, lief.dwarf.types.SetTy)

    assert isinstance(set_type.underlying_type, lief.dwarf.types.Enum)
    assert set_type.underlying_type.name == "Enum"

def test_DW_TAG_rvalue_reference_type():
    elf = lief.ELF.parse(get_sample("private/DWARF/types/DW_TAG_rvalue_reference_type.o"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert dbg_info is not None

    ty: lief.dwarf.types.Class = dbg_info.find_type("deleted")

    functions: list[lief.dwarf.Function] = list(ty.functions)
    assert len(functions) == 8

    deleted = [f for f in functions if f.name == "deleted" and f.debug_location.line == 8]

    assert len(deleted)

    parameters = deleted[0].parameters
    assert len(parameters) == 2

    rval_ref: lief.dwarf.types.RValueReference = parameters[1].type
    assert isinstance(rval_ref, lief.dwarf.types.RValueReference)
    assert rval_ref.underlying_type.name == "deleted"


def test_DW_TAG_immutable_type():
    elf = lief.ELF.parse(get_sample("private/DWARF/types/DW_TAG_immutable_type.o"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert dbg_info is not None

    CU = list(dbg_info.compilation_units)[0]
    assert CU.language.lang == lief.dwarf.CompilationUnit.Language.LANG.D
    assert CU.language.version == 0

    V = dbg_info.find_variable("a")

    imm: lief.dwarf.types.Immutable = V.type

    assert isinstance(imm, lief.dwarf.types.Immutable)
    assert imm.underlying_type.name == "char"

def test_DW_TAG_subroutine_type():
    elf = lief.ELF.parse(get_sample("private/DWARF/types/DW_TAG_subroutine_type.o"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert dbg_info is not None

    V = dbg_info.find_variable("y")

    ptr_member: lief.dwarf.types.PointerToMember = V.type

    subroutine_ty: lief.dwarf.types.Subroutine = ptr_member.underlying_type
    assert isinstance(subroutine_ty, lief.dwarf.types.Subroutine)
    params = subroutine_ty.parameters
    assert len(params) == 2

    assert params[0].type.underlying_type.name == "S"
    assert params[1].type.name == "int"

def test_DW_TAG_enumeration_type():
    elf = lief.ELF.parse(get_sample("private/DWARF/types/DW_TAG_enumeration_type.o"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert dbg_info is not None

    enum: lief.dwarf.types.Enum = dbg_info.find_type("Enum")

    assert isinstance(enum, lief.dwarf.types.Enum)

    loc = enum.location

    assert normalize_path(loc.file) == "/home/cm3/settest/src/Main.m3"
    assert loc.line == 11

def test_DW_TAG_string_type_cobol():
    elf = lief.ELF.parse(get_sample("private/DWARF/cobol_hello.o"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert dbg_info is not None

    CU: lief.dwarf.CompilationUnit = next(dbg_info.compilation_units)

    lang = CU.language

    assert lang.lang == lief.dwarf.CompilationUnit.Language.LANG.COBOL
    assert lang.version == 1985

    string_ty = dbg_info.find_type("X(10)")
    assert isinstance(string_ty, lief.dwarf.types.StringTy)

def test_DW_TAG_string_type_fortran():
    elf = lief.ELF.parse(get_sample("private/DWARF/types/DW_TAG_string_type.o"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert dbg_info is not None

    CU: lief.dwarf.CompilationUnit = next(dbg_info.compilation_units)

    lang = CU.language

    assert lang.lang == lief.dwarf.CompilationUnit.Language.LANG.FORTRAN
    assert lang.version == 1995

    string_ty = dbg_info.find_type("CHARACTER_2")
    assert isinstance(string_ty, lief.dwarf.types.StringTy)
    assert string_ty.size == 8

def test_DW_TAG_volatile_type():
    elf = lief.ELF.parse(get_sample("private/DWARF/types/DW_TAG_volatile_type.o"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert dbg_info is not None

    V = dbg_info.find_variable("sink")

    volatile: lief.dwarf.types.Volatile = V.type
    assert isinstance(volatile, lief.dwarf.types.Volatile)

    assert volatile.underlying_type.name == "int"

def test_DW_TAG_restrict_type():
    elf = lief.ELF.parse(get_sample("private/DWARF/types/DW_TAG_restrict_type.o"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert dbg_info is not None

    F = dbg_info.find_function("foo")
    params = F.parameters
    assert len(params) == 2

    restrict: lief.dwarf.types.Restrict = params[1].type.underlying_type
    assert isinstance(restrict, lief.dwarf.types.Restrict)

    assert restrict.underlying_type.underlying_type.name == "double"

def test_DW_TAG_reference_type():
    elf = lief.ELF.parse(get_sample("private/DWARF/types/DW_TAG_reference_type.o"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert dbg_info is not None

    F = dbg_info.find_function("foo")
    ret: lief.dwarf.types.Reference = F.type

    assert isinstance(ret, lief.dwarf.types.Reference)

    assert ret.underlying_type.name == "int"

def test_DW_TAG_subrange_type():
    elf = lief.ELF.parse(get_sample("private/DWARF/types/DW_TAG_subrange_type.o"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert dbg_info is not None

    V = dbg_info.find_variable("elemnt")
    array: lief.dwarf.types.Array = V.type

    size_info = array.size_info

    assert size_info.size == 1
    assert size_info.name == ""
    assert size_info.type.name == "__ARRAY_SIZE_TYPE__"

    assert array.underlying_type.name == "CHARACTER_2"

def test_DW_TAG_thrown_type():
    elf = lief.ELF.parse(get_sample("private/DWARF/types/DW_TAG_thrown_type.o"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert dbg_info is not None

    CU = next(dbg_info.compilation_units)

    lang = CU.language

    assert lang.lang == lief.dwarf.CompilationUnit.Language.LANG.SWIFT
    F = dbg_info.find_function("f")

    thrown_types = F.thrown_types
    assert len(thrown_types) == 2

    assert isinstance(thrown_types[0], lief.dwarf.types.Thrown)
    assert thrown_types[0].underlying_type.name == "Error"

    assert isinstance(thrown_types[1], lief.dwarf.types.Thrown)
    assert thrown_types[1].underlying_type.name == "DifferentError"

def test_DW_TAG_packed_type():
    elf = lief.ELF.parse(get_sample("private/DWARF/types/DW_TAG_packed_type.ps.o"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert dbg_info is not None

    packed: lief.dwarf.types.Packed = dbg_info.find_type("TFILEINFO")
    assert isinstance(packed, lief.dwarf.types.Packed)

    member = packed.members
    assert len(member) == 10

    assert member[5].offset == 10

def test_DW_TAG_shared_type():
    elf = lief.ELF.parse(get_sample("private/DWARF/D_test.bin"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert dbg_info is not None

    CU = next(dbg_info.compilation_units)

    lang = CU.language

    assert lang.lang == lief.dwarf.CompilationUnit.Language.LANG.D

    V = dbg_info.find_variable("test.flag")

    shared: lief.dwarf.types.Shared = V.type
    assert isinstance(shared, lief.dwarf.types.Shared)
    assert shared.underlying_type.name == "int"

def test_DW_TAG_interface_type():
    elf = lief.ELF.parse(get_sample("private/DWARF/java_Pig.o"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert dbg_info is not None

    CU = next(dbg_info.compilation_units)

    lang = CU.language

    assert lang.lang == lief.dwarf.CompilationUnit.Language.LANG.JAVA

    V = dbg_info.find_variable("_CD_Pig")

    array: lief.dwarf.types.Array = V.type
    assert isinstance(array, lief.dwarf.types.Array)
    assert array.size_info.type.name == "sizetype"
    assert array.size_info.size == 3

    interface: lief.dwarf.types.Interface = dbg_info.find_type("Animal")
    assert isinstance(interface, lief.dwarf.types.Interface)
