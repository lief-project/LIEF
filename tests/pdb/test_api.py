import lief
import pytest
from utils import get_sample, parse_pe

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)


def test_kernel():
    assert lief.is_pdb(get_sample("PDB/ntkrnlmp.pdb"))
    pdb = lief.pdb.load(get_sample("PDB/ntkrnlmp.pdb"))
    assert isinstance(pdb, lief.pdb.DebugInfo)

    assert pdb.age == 5
    assert pdb.guid == "bf9e1903-5978-4c2d-8796-cf5537b238b4"
    sym = pdb.find_public_symbol("MiSyncSystemPdes")

    assert sym is not None
    assert sym.name == "MiSyncSystemPdes"
    assert sym.section_name == ".text"
    assert sym.RVA == 0xED40

    units = list(pdb.compilation_units)
    assert len(units) == 1058

    cu = units[0]
    assert cu is not None
    assert cu.module_name == "* CIL *"
    assert cu.object_filename == ""

    cu = units[600]
    assert cu is not None
    assert (
        cu.module_name
        == r"e:\obj.amd64fre\minkernel\ntos\mm\mp\objfre\amd64\kernelva.obj"
    )
    assert (
        cu.object_filename
        == r"e:\obj.amd64fre\minkernel\ntos\mm\mp\objfre\amd64\mm.lib"
    )

    sources = list(cu.sources)
    assert len(sources) == 0

    cu = units[-1]
    assert cu is not None
    assert cu.module_name == r"* Linker *"
    assert cu.object_filename == r""

    syms = list(pdb.public_symbols)
    assert len(syms) == 18670

    sym0 = syms[0]
    assert sym0 is not None
    assert sym0.name == "MiSyncSystemPdes"
    assert sym0.demangled_name == sym0.name
    assert sym0.section_name == ".text"

    sym18669 = syms[18669]
    assert sym18669 is not None
    assert (
        sym18669.name == "??_C@_0CC@KGNKJKHE@heap_failure_listentry_corruptio@FNODOBFM@"
    )
    assert sym18669.demangled_name == '"heap_failure_listentry_corruptio"...'
    assert sym18669.section_name == ".text"


def test_libobjc2():
    pdb = lief.pdb.load(get_sample("PDB/libobjc2.pdb"))
    assert isinstance(pdb, lief.pdb.DebugInfo)

    assert pdb.age == 1
    assert pdb.guid == "b05a9d0d-17c3-475d-a7f2-9f5d7fafd3ad"

    units = list(pdb.compilation_units)
    assert len(units) == 95

    cu = units[0]
    assert cu is not None
    assert cu.module_name == "* CIL *"
    assert cu.object_filename == ""

    sources = list(cu.sources)
    assert len(sources) == 0

    cu = units[2]
    assert cu is not None
    assert (
        cu.module_name
        == r"C:\Users\Dustin\Projects\src\thirdparty\WinObjC2\deps\3rdparty\libobjc2\msvc\Win32\Release\Universal Windows\libobjc2.exp"
    )
    assert (
        cu.object_filename
        == r"C:\Users\Dustin\Projects\src\thirdparty\WinObjC2\deps\3rdparty\libobjc2\msvc\Win32\Release\Universal Windows\libobjc2.exp"
    )

    sources = list(cu.sources)
    assert len(sources) == 1
    assert (
        sources[0]
        == r"C:\Users\Dustin\Projects\src\thirdparty\WinObjC2\deps\3rdparty\libobjc2\msvc\libobjc2.def"
    )

    syms = list(pdb.public_symbols)
    assert len(syms) == 756

    sym0 = syms[0]
    assert sym0 is not None
    assert sym0.name == "_sel_getType_np"
    assert sym0.demangled_name == sym0.name

    sym579 = syms[579]
    assert sym579 is not None
    assert sym579.name == "??1bad_array_new_length@std@@UAE@XZ"
    assert (
        sym579.demangled_name
        == "public: virtual __thiscall std::bad_array_new_length::~bad_array_new_length(void)"
    )
    assert sym579.section_name == ".text"
    assert sym579.RVA == 0x15082

    cu = units[2]
    assert cu is not None
    assert len(list(cu.functions)) == 0

    cu = units[3]
    assert cu is not None
    functions = list(cu.functions)
    assert len(functions) == 4

    fn0 = functions[0]
    assert fn0 is not None
    assert fn0.name == "objc_exception_throw"
    assert fn0.RVA == 0x13F00
    assert fn0.code_size == 0x6B0
    assert fn0.section_name == ".text"
    fn1 = functions[1]
    assert fn1 is not None
    assert fn1.name == "objc_exception_rethrow"
    assert fn1.RVA == 0x145B0
    assert fn1.code_size == 9
    assert fn1.section_name == ".text"
    fn2 = functions[2]
    assert fn2 is not None
    assert (
        fn2.name
        == r"std::basic_string<char,std::char_traits<char>,std::allocator<char> >::_Reallocate_grow_by<`lambda at C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\VC\Tools\MSVC\14.16.27023\include\xstring:2582:4',const char *,unsigned int>"
    )
    fn3 = functions[3]
    assert fn3 is not None
    assert (
        fn3.name
        == "std::basic_string<char,std::char_traits<char>,std::allocator<char> >::_Xlen"
    )

    loc = fn0.debug_location
    assert (
        loc.file
        == r"C:\Users\Dustin\Projects\src\thirdparty\WinObjC2\deps\3rdparty\libobjc2\eh_win32_msvc.cc"
    )
    assert loc.line == 95

    loc = fn3.debug_location
    assert (
        loc.file
        == r"C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\VC\Tools\MSVC\14.16.27023\include\xstring"
    )
    assert loc.line == 4004


def test_external_load():
    pe = parse_pe("private/PE/LIEF-arm64.dll")
    assert pe is not None
    pe.load_debug_info(get_sample("private/PDB/LIEF-arm64.pdb"))
    assert pe.debug_info is not None
    assert isinstance(pe.debug_info, lief.pdb.DebugInfo)

    assert (
        len(list(pe.disassemble("??1?$digit_grouping@D@detail@v10@fmt@@QEAA@XZ")))
        == 9538
    )
