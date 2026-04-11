from typing import cast

import lief
import pytest
from utils import get_debug_info, normalize_path, parse_elf

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)


def test_simple_c():
    elf = parse_elf("ELF/simple-gcc-c.bin")

    dbg_info = get_debug_info(elf)
    assert isinstance(dbg_info, lief.dwarf.DebugInfo)

    units = list(dbg_info.compilation_units)
    assert len(units) == 1

    cu = units[0]
    assert cu is not None
    assert cu.compilation_dir == "/src"
    assert cu.producer == "GNU C17 13.2.0 -mtune=generic -march=x86-64 -g"
    assert cu.name == "test.c"
    assert cu.language.lang == lief.dwarf.CompilationUnit.Language.LANG.C

    assert cu.low_address == 0x401126
    assert cu.high_address == 0x40113B
    assert cu.size == 21

    ranges = cu.ranges
    assert len(ranges) == 1
    assert ranges[0].low == 0x401126
    assert ranges[0].high == 0x40113B

    assert cu.find_function("main") is not None
    assert cu.find_function("_main_") is None

    assert cu.find_function(0x401126) is not None
    assert cu.find_function(0x123456) is None

    main_func = dbg_info.find_function("main")
    assert main_func is not None

    functions = list(cu.functions)
    assert len(functions) == 1

    main_func = functions[0]
    assert main_func is not None
    assert main_func.name == "main"
    assert main_func.linkage_name == ""
    assert main_func.address == 0x401126
    assert not main_func.is_artificial
    assert main_func.size == 0x15
    assert normalize_path(main_func.debug_location.file) == "/src/test.c"
    assert main_func.debug_location.line == 3

    ranges = main_func.ranges
    assert len(ranges) == 1
    assert ranges[0].low == 0x401126
    assert ranges[0].high == 0x40113B

    params = main_func.parameters
    assert len(params) == 0

    f_by_addr = dbg_info.find_function(0x401126)
    assert f_by_addr is not None
    assert f_by_addr.name == "main"

    variables = list(main_func.variables)
    assert len(variables) == 0


@pytest.mark.private
def test_lief():
    elf = parse_elf("private/DWARF/libLIEF.so")

    dbg_info = get_debug_info(elf)
    assert dbg_info.find_function(0xDEADC0DE) is None
    assert (
        cast(lief.dwarf.Function, dbg_info.find_function(0x2E6B40)).name
        == "mbedtls_aes_free"
    )

    assert dbg_info.find_function("_mbedtls_ct_memcmp_") is None
    assert (
        cast(lief.dwarf.Function, dbg_info.find_function("mbedtls_ct_memcmp")).address
        == 0x002FB700
    )

    assert (
        dbg_info.find_type(
            "unique_ptr<LIEF::BinaryStream, std::default_delete<LIEF::BinaryStream> >"
        )
        is not None
    )
    assert dbg_info.find_type("unique_ptr<foo>") is None

    parse = dbg_info.find_function(
        "_ZN4LIEF2PE6Parser5parseERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEERKNS0_12ParserConfigE"
    )
    assert parse is not None

    params = parse.parameters
    assert len(params) == 2
    assert params[0] is not None
    assert params[0].name == "filename"
    assert params[1] is not None
    assert params[1].name == "conf"

    assert isinstance(params[0].type, lief.dwarf.Type)
    assert isinstance(params[1].type, lief.dwarf.Type)

    assert params[0].type.name is None
    assert params[1].type.name is None

    # tl::expected<LIEF::ok_t, lief_errors> LIEF::PE::Parser::parse_delay_names_table<LIEF::PE::details::PE32>(LIEF::PE::DelayImport&, unsigned int)
    f2 = dbg_info.find_function(
        "_ZN4LIEF2PE6Parser23parse_delay_names_tableINS0_7details4PE32EEEN2tl8expectedINS_4ok_tE11lief_errorsEERNS0_11DelayImportEj"
    )
    assert f2 is not None
    f2_scope = f2.scope
    assert f2_scope is not None
    assert f2_scope.name == "/workdir/branches/main/src/PE/Parser.cpp"

    params = f2.parameters
    assert len(params) == 4

    assert params[0] is not None
    assert params[0].name == "this"
    assert isinstance(params[0].type, lief.dwarf.types.Pointer)
    p0_underlying = params[0].type.underlying_type
    assert p0_underlying is not None
    assert p0_underlying.kind == lief.dwarf.Type.KIND.CLASS
    assert p0_underlying.name == "Parser"
    p0_class = cast(lief.dwarf.types.ClassLike, p0_underlying)
    assert len(p0_class.members) == 5

    assert params[1] is not None
    assert params[1].name == "import"
    p1_type = params[1].type
    assert p1_type is not None
    assert p1_type.kind == lief.dwarf.Type.KIND.REF

    assert params[2] is not None
    assert params[2].name == "names_offset"
    p2_type = params[2].type
    assert p2_type is not None
    assert p2_type.kind == lief.dwarf.Type.KIND.TYPEDEF
    assert p2_type.name == "uint32_t"

    assert isinstance(p2_type, lief.dwarf.types.Typedef)
    p2_underlying = p2_type.underlying_type
    assert p2_underlying is not None
    assert p2_underlying.kind == lief.dwarf.Type.KIND.TYPEDEF
    assert p2_underlying.name == "__uint32_t"

    assert params[3] is not None
    assert params[3].name == "PE_T"
    assert isinstance(params[3], lief.dwarf.parameters.TemplateType)

    CUS = list(dbg_info.compilation_units)
    assert len(CUS) == 366
    cu0 = CUS[0]
    assert cu0 is not None
    imported_functions = list(cu0.imported_functions)
    assert len(imported_functions) == 177

    f0 = imported_functions[0]
    assert f0 is not None
    assert f0.name == "btowc"


def test_scope():
    elf = parse_elf("DWARF/scope_3")
    dbg_info = get_debug_info(elf)
    counter_var = dbg_info.find_variable("counter")
    assert counter_var is not None
    counter_scope = counter_var.scope
    assert counter_scope is not None
    assert counter_scope.type == lief.dwarf.Scope.TYPE.FUNCTION

    gvar_init = dbg_info.find_function("__cxx_global_var_init")
    assert gvar_init is not None
    assert gvar_init.is_artificial

    ty = cast(lief.dwarf.types.Class, dbg_info.find_type("MyClass"))
    m0 = ty.find_member(0)
    assert m0 is not None
    assert m0.name == "value_"
    m1 = ty.find_member(1)
    assert m1 is not None
    assert m1.name == "value_"
    assert ty.find_member(8) is None


def test_imported_functions():
    elf = parse_elf("ELF/simple-gcc-c.bin")

    dbg_info = get_debug_info(elf)
    assert isinstance(dbg_info, lief.dwarf.DebugInfo)

    units = list(dbg_info.compilation_units)
    assert len(units) == 1
    cu = units[0]
    assert cu is not None
    functions = list(cu.imported_functions)
    assert len(functions) == 0


def test_disassembler():
    elf = parse_elf("private/DWARF/libLIEF.so")

    dbg_info = get_debug_info(elf)
    mbedtls_aes_free = dbg_info.find_function(0x2E6B40)

    assert mbedtls_aes_free is not None
    insts = list(mbedtls_aes_free.instructions)
    assert len(insts) == 5


def test_addr():
    elf = parse_elf("DWARF/vars_1.elf")

    dbg_info = get_debug_info(elf)
    assert isinstance(dbg_info, lief.dwarf.DebugInfo)

    main = dbg_info.find_function("main")
    assert main is not None
    assert main.address == 0x1180

    insts = list(main.instructions)
    assert len(insts) == 79


def test_issue_1259():
    elf = parse_elf("DWARF/issue-1259")

    dbg_info = get_debug_info(elf)
    assert isinstance(dbg_info, lief.dwarf.DebugInfo)

    my_bitfield = dbg_info.find_variable("my_bitfield")
    assert my_bitfield is not None
    ty = my_bitfield.type
    assert ty is not None
    ty_classlike = cast(lief.dwarf.types.ClassLike, ty)
    assert [m.bit_offset for m in ty_classlike.members] == [7, 4, 0]

    assert [m.bit_size for m in ty_classlike.members] == [1, 2, 4]
