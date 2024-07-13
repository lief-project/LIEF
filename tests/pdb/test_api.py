import lief
import pytest
from utils import get_sample

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

def test_kernel():
    pdb = lief.pdb.load(get_sample("PDB/ntkrnlmp.pdb"))
    assert isinstance(pdb, lief.pdb.DebugInfo)

    assert pdb.age == 5
    assert pdb.guid == "bf9e1903-5978-4c2d-8796-cf5537b238b4"
    sym = pdb.find_public_symbol("MiSyncSystemPdes")

    assert sym is not None
    assert sym.name == "MiSyncSystemPdes"
    assert sym.section_name == ".text"
    assert sym.RVA == 0xed40

    units = list(pdb.compilation_units)
    assert len(units) == 1058

    cu = units[0]
    assert cu.module_name == "* CIL *"
    assert cu.object_filename == ""

    cu = units[600]
    assert cu.module_name == r"e:\obj.amd64fre\minkernel\ntos\mm\mp\objfre\amd64\kernelva.obj"
    assert cu.object_filename == r"e:\obj.amd64fre\minkernel\ntos\mm\mp\objfre\amd64\mm.lib"

    sources = list(cu.sources)
    assert len(sources) == 0

    cu = units[-1]
    assert cu.module_name == r"* Linker *"
    assert cu.object_filename == r""

    syms = list(pdb.public_symbols)
    assert len(syms) == 18670

    assert syms[0].name == "MiSyncSystemPdes"
    assert syms[0].demangled_name == syms[0].name
    assert syms[0].section_name == ".text"

    assert syms[18669].name == "??_C@_0CC@KGNKJKHE@heap_failure_listentry_corruptio@FNODOBFM@"
    assert syms[18669].demangled_name == '"heap_failure_listentry_corruptio"...'
    assert syms[18669].section_name == ".text"

def test_libobjc2():
    pdb = lief.pdb.load(get_sample("PDB/libobjc2.pdb"))
    assert isinstance(pdb, lief.pdb.DebugInfo)

    assert pdb.age == 1
    assert pdb.guid == "b05a9d0d-17c3-475d-a7f2-9f5d7fafd3ad"

    units = list(pdb.compilation_units)
    assert len(units) == 95

    cu = units[0]
    assert cu.module_name == "* CIL *"
    assert cu.object_filename == ""

    sources = list(cu.sources)
    assert len(sources) == 0

    cu = units[2]
    assert cu.module_name == r"C:\Users\Dustin\Projects\src\thirdparty\WinObjC2\deps\3rdparty\libobjc2\msvc\Win32\Release\Universal Windows\libobjc2.exp"
    assert cu.object_filename == r"C:\Users\Dustin\Projects\src\thirdparty\WinObjC2\deps\3rdparty\libobjc2\msvc\Win32\Release\Universal Windows\libobjc2.exp"

    sources = list(cu.sources)
    assert len(sources) == 1
    assert sources[0] == r"C:\Users\Dustin\Projects\src\thirdparty\WinObjC2\deps\3rdparty\libobjc2\msvc\libobjc2.def"

    syms = list(pdb.public_symbols)
    assert len(syms) == 756

    assert syms[0].name == "_sel_getType_np"
    assert syms[0].demangled_name == syms[0].name

    assert syms[579].name == "??1bad_array_new_length@std@@UAE@XZ"
    assert syms[579].demangled_name == 'public: virtual __thiscall std::bad_array_new_length::~bad_array_new_length(void)'
    assert syms[579].section_name == ".text"
    assert syms[579].RVA == 0x15082

    cu = units[2]
    assert len(list(cu.functions)) == 0

    cu = units[3]
    functions = list(cu.functions)
    assert len(functions) == 4

    assert functions[0].name == "objc_exception_throw"
    assert functions[0].RVA == 0x13f00
    assert functions[0].code_size == 0x6b0
    assert functions[0].section_name == ".text"
    assert functions[1].name == "objc_exception_rethrow"
    assert functions[1].RVA == 0x145b0
    assert functions[1].code_size == 9
    assert functions[1].section_name == ".text"
    assert functions[2].name == r"std::basic_string<char,std::char_traits<char>,std::allocator<char> >::_Reallocate_grow_by<`lambda at C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\VC\Tools\MSVC\14.16.27023\include\xstring:2582:4',const char *,unsigned int>"
    assert functions[3].name == "std::basic_string<char,std::char_traits<char>,std::allocator<char> >::_Xlen"

    loc = functions[0].debug_location
    assert loc.file == r"C:\Users\Dustin\Projects\src\thirdparty\WinObjC2\deps\3rdparty\libobjc2\eh_win32_msvc.cc"
    assert loc.line == 95

    loc = functions[3].debug_location
    assert loc.file == r"C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\VC\Tools\MSVC\14.16.27023\include\xstring"
    assert loc.line == 4004
