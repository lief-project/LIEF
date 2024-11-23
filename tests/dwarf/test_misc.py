import lief
import pytest
from utils import get_sample, normalize_path

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

def test_simple_c():
    elf = lief.ELF.parse(get_sample("ELF/simple-gcc-c.bin"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert isinstance(dbg_info, lief.dwarf.DebugInfo)

    units = list(dbg_info.compilation_units)
    assert len(units) == 1

    cu = units[0]
    assert cu.compilation_dir == "/src"
    assert cu.producer == "GNU C17 13.2.0 -mtune=generic -march=x86-64 -g"
    assert cu.name == "test.c"
    assert cu.language.lang == lief.dwarf.CompilationUnit.Language.LANG.C

    assert cu.low_address == 0x401126
    assert cu.high_address == 0x40113b
    assert cu.size == 21

    ranges = cu.ranges
    assert len(ranges) == 1
    assert ranges[0].low == 0x401126
    assert ranges[0].high == 0x40113b

    assert cu.find_function("main") is not None
    assert cu.find_function("_main_") is None

    assert cu.find_function(0x401126) is not None
    assert cu.find_function(0x123456) is None

    main_func = dbg_info.find_function("main")
    assert main_func is not None

    functions = list(cu.functions)
    assert len(functions) == 1

    main_func = functions[0]
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
    assert ranges[0].high == 0x40113b

    params = main_func.parameters
    assert len(params) == 0

    assert dbg_info.find_function(0x401126).name == "main"

    variables = list(functions[0].variables)
    assert len(variables) == 0


def test_lief():
    elf = lief.ELF.parse(get_sample("private/DWARF/libLIEF.so"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert dbg_info.find_function(0xdeadc0de) is None
    assert dbg_info.find_function(0x2e6b40).name == "mbedtls_aes_free"

    assert dbg_info.find_function("_mbedtls_ct_memcmp_") is None
    assert dbg_info.find_function("mbedtls_ct_memcmp").address == 0x002fb700

    assert dbg_info.find_type("unique_ptr<LIEF::BinaryStream, std::default_delete<LIEF::BinaryStream> >") is not None
    assert dbg_info.find_type("unique_ptr<foo>") is None

    parse = dbg_info.find_function("_ZN4LIEF2PE6Parser5parseERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEERKNS0_12ParserConfigE")
    assert parse is not None

    params = parse.parameters
    assert len(params) == 2
    assert params[0].name == "filename"
    assert params[1].name == "conf"

    assert isinstance(params[0].type, lief.dwarf.Type)
    assert isinstance(params[1].type, lief.dwarf.Type)

    assert params[0].type.name is None
    assert params[1].type.name is None

    # tl::expected<LIEF::ok_t, lief_errors> LIEF::PE::Parser::parse_delay_names_table<LIEF::PE::details::PE32>(LIEF::PE::DelayImport&, unsigned int)
    f2 = dbg_info.find_function("_ZN4LIEF2PE6Parser23parse_delay_names_tableINS0_7details4PE32EEEN2tl8expectedINS_4ok_tE11lief_errorsEERNS0_11DelayImportEj")
    assert f2 is not None
    assert f2.scope.name == "/workdir/branches/main/src/PE/Parser.cpp"

    params = f2.parameters
    assert len(params) == 4

    assert params[0].name == "this"
    assert isinstance(params[0].type, lief.dwarf.types.Pointer)
    assert params[0].type.underlying_type.kind == lief.dwarf.Type.KIND.CLASS
    assert params[0].type.underlying_type.name == "Parser"
    assert len(params[0].type.underlying_type.members) == 5

    assert params[1].name == "import"
    assert params[1].type.kind == lief.dwarf.Type.KIND.REF

    assert params[2].name == "names_offset"
    p2_type = params[2].type
    assert p2_type.kind == lief.dwarf.Type.KIND.TYPEDEF
    assert p2_type.name == "uint32_t"

    assert isinstance(p2_type, lief.dwarf.types.Typedef)
    assert p2_type.underlying_type.kind == lief.dwarf.Type.KIND.TYPEDEF
    assert p2_type.underlying_type.name == "__uint32_t"

    assert params[3].name == "PE_T"
    assert isinstance(params[3], lief.dwarf.parameters.TemplateType)

    CUS = list(dbg_info.compilation_units)
    assert len(CUS) == 366
    imported_functions = list(CUS[0].imported_functions)
    assert len(imported_functions) == 177

    assert imported_functions[0].name == "btowc"

def test_scope():
    elf = lief.ELF.parse(get_sample("DWARF/scope_3"))
    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    counter_var = dbg_info.find_variable("counter")
    assert counter_var.scope.type == lief.dwarf.Scope.TYPE.FUNCTION

    gvar_init = dbg_info.find_function("__cxx_global_var_init")
    assert gvar_init.is_artificial

    ty: lief.dwarf.types.Class = dbg_info.find_type("MyClass")
    assert ty.find_member(0).name == "value_"
    assert ty.find_member(1).name == "value_"
    assert ty.find_member(8) is None

def test_imported_functions():
    elf = lief.ELF.parse(get_sample("ELF/simple-gcc-c.bin"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert isinstance(dbg_info, lief.dwarf.DebugInfo)

    units = list(dbg_info.compilation_units)
    assert len(units) == 1
    cu = units[0]
    functions = list(cu.imported_functions)
    assert len(functions) == 0

def test_disassembler():
    elf = lief.ELF.parse(get_sample("private/DWARF/libLIEF.so"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    mbedtls_aes_free = dbg_info.find_function(0x2e6b40)

    assert mbedtls_aes_free is not None
    insts = list(mbedtls_aes_free.instructions)
    assert len(insts) == 5

def test_addr():
    elf = lief.ELF.parse(get_sample("DWARF/vars_1.elf"))

    dbg_info: lief.dwarf.DebugInfo = elf.debug_info
    assert isinstance(dbg_info, lief.dwarf.DebugInfo)

    main = dbg_info.find_function("main")
    assert main is not None
    assert main.address == 0x1180

    insts = list(main.instructions)
    assert len(insts) == 79
