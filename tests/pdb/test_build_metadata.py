import lief
import pytest
from utils import get_sample, has_private_samples

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

@pytest.mark.skipif(not has_private_samples(), reason="needs private samples")
def test_simple():
    pdb = lief.pdb.load(get_sample("private/PDB/LIEF.pdb"))
    assert isinstance(pdb, lief.pdb.DebugInfo)

    CUs = list(pdb.compilation_units)
    assert len(CUs) == 434

    CU = CUs[425]
    assert CU.module_name == "* Linker Generated Manifest RES *"
    metadata: lief.pdb.BuildMetadata = CU.build_metadata

    assert metadata.frontend_version.major == 0
    assert metadata.frontend_version.minor == 0
    assert metadata.frontend_version.build == 0
    assert metadata.frontend_version.qfe == 0

    assert metadata.backend_version.major == 14
    assert metadata.backend_version.minor == 36
    assert metadata.backend_version.build == 32537
    assert metadata.backend_version.qfe == 0

    assert metadata.version == "Microsoft (R) CVTRES"
    assert metadata.language == lief.pdb.BuildMetadata.LANG.CVTRES
    assert metadata.target_cpu == lief.pdb.BuildMetadata.CPU.X64

    CU = CUs[424]
    metadata: lief.pdb.BuildMetadata = CU.build_metadata
    assert metadata.build_info.command_line == ' -Zc:threadSafeInit- -w34640 -Zc:char8_t -w14265 -w14242 -w14254 -w14287 -w14296 -w14302 -w14388 -w14549 -w14619 -w14905 -w14906 -Zc:inline- -guard:cf -diagnostics:caret -ZH:SHA_256 -experimental:deterministic -wd5049 -permissive- -X'

    CU = CUs[433]
    assert CU.module_name == "* Linker *"
    metadata: lief.pdb.BuildMetadata = CU.build_metadata

    assert metadata.version == "Microsoft (R) LINK"
    assert metadata.language == lief.pdb.BuildMetadata.LANG.LINK
    assert metadata.target_cpu == lief.pdb.BuildMetadata.CPU.X64

    assert metadata.env == [
        'cwd', 'C:\\Users\\romai\\dev\\LIEF\\branches\\build_test',
        'exe', 'C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.36.32532\\bin\\HostX64\\x64\\link.exe',
        'pdb', 'C:\\Users\\romai\\dev\\LIEF\\branches\\build_test\\Debug\\LIEF.pdb',
        'cmd', ' /ERRORREPORT:PROMPT /OUT:C:\\Users\\romai\\dev\\LIEF\\branches\\build_test\\Debug\\LIEF.dll /INCREMENTAL /ILK:LIB_LIEF.dir\\Debug\\LIEF.ilk /NOLOGO /MANIFEST "/MANIFESTUAC:level=\'asInvoker\' uiAccess=\'false\'" /manifest:embed /DEBUG /PDB:C:/Users/romai/dev/LIEF/branches/build_test/Debug/LIEF.pdb /SUBSYSTEM:CONSOLE /TLBID:1 /DYNAMICBASE /NXCOMPAT /IMPLIB:C:/Users/romai/dev/LIEF/branches/build_test/Debug/LIEF.lib /MACHINE:X64 /machine:x64 /DLL'
    ]

    CU = CUs[384]
    metadata: lief.pdb.BuildMetadata = CU.build_metadata

    assert metadata.version == "Microsoft (R) Macro Assembler"
    assert metadata.language == lief.pdb.BuildMetadata.LANG.MASM
    assert metadata.target_cpu == lief.pdb.BuildMetadata.CPU.X64

    CU = CUs[0]
    metadata: lief.pdb.BuildMetadata = CU.build_metadata

    assert metadata.frontend_version.major == 19
    assert metadata.frontend_version.minor == 36
    assert metadata.frontend_version.build == 32537
    assert metadata.frontend_version.qfe == 0

    assert metadata.backend_version.major == 19
    assert metadata.backend_version.minor == 36
    assert metadata.backend_version.build == 32537
    assert metadata.backend_version.qfe == 0

    assert metadata.version == "Microsoft (R) Optimizing Compiler"
    assert metadata.language == lief.pdb.BuildMetadata.LANG.CPP
    assert metadata.target_cpu == lief.pdb.BuildMetadata.CPU.X64
