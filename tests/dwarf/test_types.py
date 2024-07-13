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
    assert len(types) == 477

    # Pointer type
    ptr_type: lief.dwarf.types.Pointer = types[12]
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
    struct_type: lief.dwarf.types.Pointer = types[327]
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
    array_type: lief.dwarf.types.Pointer = types[417]
    assert array_type.kind == lief.dwarf.Type.KIND.ARRAY
    assert array_type.name is None
    assert array_type.size == 40
    assert isinstance(array_type, lief.dwarf.types.Array)

    underlying_array_type = array_type.underlying_type
    assert isinstance(underlying_array_type, lief.dwarf.types.Base)

    # Const type
    cst_type: lief.dwarf.types.Pointer = types[468]
    assert cst_type.kind == lief.dwarf.Type.KIND.CONST
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
