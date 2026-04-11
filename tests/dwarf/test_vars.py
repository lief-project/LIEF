from typing import cast

import lief
import pytest
from utils import get_debug_info, normalize_path, parse_elf

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

    g_vars = list(cu.variables)
    assert len(g_vars) == 34

    assert g_vars[0] is not None
    assert g_vars[0].name == "piecewise_construct"
    assert g_vars[0].is_constexpr

    assert g_vars[6] is not None
    assert g_vars[6].name == "g_map"
    assert g_vars[7] is not None
    assert g_vars[7].name == "g_int"
    assert g_vars[8] is not None
    assert g_vars[8].name == "IS_CONSTEXPR"

    g_int = cu.find_variable("g_int")
    assert g_int is not None
    assert g_int.address is None
    assert g_int.size == 4
    assert not g_int.is_constexpr
    assert normalize_path(g_int.debug_location.file) == "/workdir/DWARF/vars_1.cpp"
    assert g_int.debug_location.line == 8

    g_int_type = g_int.type
    assert g_int_type is not None
    assert g_int_type.kind == lief.dwarf.Type.KIND.BASE
    assert isinstance(g_int_type, lief.dwarf.types.Base)
    assert g_int_type.name == "int"
    assert g_int_type.size == 4
    assert g_int_type.encoding == lief.dwarf.types.Base.ENCODING.SIGNED
    assert g_int_type.location.file == ""
    assert g_int_type.location.line == 0
    assert not g_int_type.is_unspecified

    assert cu.find_variable(0) is None
    assert cu.find_variable("foo") is None

    g_map = cu.find_variable("g_map")
    g_map_by_addr = cu.find_variable(0x40E0)
    assert g_map_by_addr is not None
    assert g_map_by_addr.name == "g_map"
    assert g_map is not None
    assert g_map.address == 0x40E0
    assert not g_map.is_constexpr
    assert normalize_path(g_map.debug_location.file) == "/workdir/DWARF/vars_1.cpp"
    assert g_map.debug_location.line == 7

    assert dbg_info.find_variable(0x40E0) is not None
    found_var = dbg_info.find_variable(0x40E0)
    assert found_var is not None
    assert found_var.name == "g_map"
    assert dbg_info.find_variable(0) is None
    assert dbg_info.find_function(0) is None

    g_map_type = cast(lief.dwarf.types.Class, g_map.type)
    assert isinstance(g_map_type, lief.dwarf.types.Class)
    members = g_map_type.members

    assert len(members) == 1

    assert members[0].name == "_M_h"
    assert members[0].offset == 0
    assert members[0].type is not None
    assert members[0].type.kind == lief.dwarf.Type.KIND.TYPEDEF

    main = dbg_info.find_function("main")
    assert main is not None
    main_vars = list(main.variables)
    assert len(main_vars) == 3

    assert main_vars[0] is not None
    assert main_vars[0].name == "local_var_1"
    assert main_vars[0].address == -0x48
    assert main_vars[0].is_stack_based
    assert main_vars[0].size == 4
    assert not main_vars[0].is_constexpr
    assert (
        normalize_path(main_vars[0].debug_location.file) == "/workdir/DWARF/vars_1.cpp"
    )
    assert main_vars[0].debug_location.line == 13

    local_var_1_type = main_vars[0].type
    assert isinstance(local_var_1_type, lief.dwarf.types.Base)

    assert main_vars[1] is not None
    assert main_vars[1].name == "local_var_2"
    assert main_vars[1].size == 4

    assert main_vars[2] is not None
    assert main_vars[2].name == "local_var_3"
    assert main_vars[2].size == 8

    local_var_3_type = main_vars[2].type
    assert isinstance(local_var_3_type, lief.dwarf.types.Base)


@pytest.mark.private
def test_vars_lief():
    elf = parse_elf("private/DWARF/libLIEF.so")

    dbg_info = cast(lief.dwarf.DebugInfo, elf.debug_info)
    id_var = dbg_info.find_variable("_ZN3fmt3v1012format_facetISt6localeE2idE")
    assert id_var is not None
    id_var = dbg_info.find_variable("fmt::v10::format_facet<std::locale>::id")
    assert id_var is not None

    assert id_var.address == 0x44F5F8
    assert id_var.linkage_name == "_ZN3fmt3v1012format_facetISt6localeE2idE"
    assert id_var.name == "id"
    assert id_var.size == 8
    assert (
        normalize_path(id_var.debug_location.file)
        == "/workdir/build/lief_spdlog_project-prefix/src/lief_spdlog_project/include/spdlog/fmt/bundled/format.h"
    )
    assert id_var.debug_location.line == 1074
    assert id_var.type is not None
    assert id_var.type.kind == lief.dwarf.Type.KIND.CLASS

    assert dbg_info.find_variable(0x44F5F8) is not None
    assert dbg_info.find_variable(0xDEADC0DE) is None


def test_scope():
    elf = parse_elf("DWARF/scope")
    dbg_info = cast(lief.dwarf.DebugInfo, elf.debug_info)

    var = dbg_info.find_variable("var")
    assert var is not None
    var_type = var.type
    assert isinstance(var_type, lief.dwarf.types.Union)

    assert var_type.name == "Union1"

    scope = var_type.scope
    assert scope is not None
    assert scope.name == "Struct1"
    assert scope.type == lief.dwarf.Scope.TYPE.STRUCT

    scope = scope.parent
    assert scope is not None
    assert scope.name == "Class1"
    assert scope.type == lief.dwarf.Scope.TYPE.CLASS

    scope = scope.parent
    assert scope is not None
    assert scope.name == "ns2"
    assert scope.type == lief.dwarf.Scope.TYPE.NAMESPACE

    scope = scope.parent
    assert scope is not None
    assert scope.name == "ns1"
    assert scope.type == lief.dwarf.Scope.TYPE.NAMESPACE

    scope = scope.parent
    assert scope is not None
    assert scope.name == "scope.cpp"
    assert scope.type == lief.dwarf.Scope.TYPE.COMPILATION_UNIT

    scope = scope.parent
    assert scope is None

    elf = parse_elf("DWARF/scope_2")
    dbg_info = cast(lief.dwarf.DebugInfo, elf.debug_info)

    var = dbg_info.find_variable("_ZN3foo3bar3baz3quxE")
    assert var is not None
    var_type_2 = var.type
    assert var_type_2 is not None
    var_scope_2 = var_type_2.scope
    assert var_scope_2 is not None
    assert var_scope_2.chained("::") == ""
    assert var.scope is not None
    assert var.scope.chained("::") == "foo::bar::baz"
