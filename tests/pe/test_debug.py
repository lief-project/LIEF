import lief
import json
from utils import get_sample
from typing import cast
from pathlib import Path
from hashlib import md5
from textwrap import dedent

def test_pgo():
    path  = get_sample("PE/PE32_x86_binary_PGO-LTCG.exe")
    sample = lief.PE.parse(path)

    debugs = sample.debug
    assert len(debugs) == 3
    assert debugs[0].type == lief.PE.Debug.TYPES.CODEVIEW
    assert debugs[1].type == lief.PE.Debug.TYPES.VC_FEATURE
    assert debugs[2].type == lief.PE.Debug.TYPES.POGO

    assert debugs[0].section.name == ".rdata"
    assert md5(debugs[0].payload).hexdigest() == "5eba9e8204124f6d760e2d93948c3155"

    vc_feature = debugs[1]
    assert vc_feature.copy() == vc_feature
    assert vc_feature.characteristics == 0
    assert vc_feature.major_version == 0
    assert vc_feature.minor_version == 0
    assert vc_feature.sizeof_data == 0x14
    assert vc_feature.addressof_rawdata == 0x7f54
    assert vc_feature.pointerto_rawdata == 0x6754
    assert vc_feature.timestamp == 0x5c16251a
    print(vc_feature)

    assert debugs[2].copy() == debugs[2]
    assert debugs[1] != debugs[0]

    pgo = cast(lief.PE.Pogo, debugs[-1])
    print(pgo)
    assert isinstance(pgo, lief.PE.Pogo)
    assert len(pgo.entries) == 33
    assert pgo.signature == lief.PE.Pogo.SIGNATURES.LCTG
    assert len(pgo.copy().entries) == len(pgo.entries) # type: ignore
    entries = pgo.entries
    assert entries[0].name == ".text$mn"
    assert entries[0].size == 0x5210
    assert entries[0].start_rva == 0x1000

    assert entries[-1].name == ".rsrc$02"
    assert entries[-1].size == 0x0180
    assert entries[-1].start_rva == 0xb060

    assert entries[0].copy() == entries[0]
    assert entries[1].copy() != entries[-2]

def test_guid():
    path = get_sample('PE/ntoskrnl.exe')
    sample = lief.PE.parse(path)
    cv_1 = sample.codeview_pdb
    assert cv_1 is not None
    assert cv_1.guid == "fcb9afc6-a352-f97b-17cf-5f981382c782"

    path = get_sample('PE/PE64_x86-64_binary_ConsoleApplication1.exe')
    sample = lief.PE.parse(path)
    cv_2 = sample.codeview_pdb
    assert cv_2 is not None
    assert cv_2.guid == "b6e3d9f5-7147-4f01-a203-aa477c4aba54"

def test_code_view_pdb():
    path = Path(get_sample('PE/PE64_x86-64_binary_ConsoleApplication1.exe'))
    sample = lief.PE.parse(path)

    assert sample.has_debug

    for d in sample.debug:
        print(d)

    debug_code_view = list(filter(lambda deb: isinstance(deb, lief.PE.CodeViewPDB), sample.debug))
    assert len(debug_code_view) == 1

    code_view = cast(lief.PE.CodeViewPDB, debug_code_view[0])

    assert code_view.cv_signature == lief.PE.CodeView.SIGNATURES.PDB_70
    assert code_view.signature == [245, 217, 227, 182, 71, 113, 1, 79, 162, 3, 170, 71, 124, 74, 186, 84]
    assert code_view.age == 1
    assert code_view.filename == r"c:\users\romain\documents\visual studio 2015\Projects\HelloWorld\x64\Release\ConsoleApplication1.pdb"
    assert code_view.copy() == code_view

    assert hash(code_view.parent) == hash(code_view.copy().parent) # type: ignore

    assert isinstance(code_view.parent, lief.PE.CodeView)

    json_view = json.loads(lief.to_json(code_view))
    assert json_view == {
        'addressof_rawdata': 8996,
        'characteristics': 0,
        'age': 1,
        'cv_signature': 'PDB_70',
        'filename': r'c:\users\romain\documents\visual studio 2015\Projects\HelloWorld\x64\Release\ConsoleApplication1.pdb',
        'signature': [245, 217, 227, 182, 71, 113, 1, 79, 162, 3, 170, 71, 124, 74, 186, 84],
        'major_version': 0,
        'minor_version': 0,
        'pointerto_rawdata': 5412,
        'sizeof_data': 125,
        'timestamp': 1459952944,
        'type': 'CODEVIEW'
    }
    assert print(code_view) is None

    cv1 = lief.PE.CodeView()
    cv2 = lief.PE.CodeView(lief.PE.CodeView.SIGNATURES.CV_50)
    assert cv1.copy() != cv2

def test_repro():
    lief.logging.set_level(lief.logging.LEVEL.DEBUG)
    path = get_sample('PE/test.debug.repro.exe')

    sample = lief.PE.parse(path)
    for d in sample.debug:
        print(d)

    assert len(sample.debug) == 2

    assert isinstance(sample.debug[0], lief.PE.Pogo)
    pogo = cast(lief.PE.Pogo, sample.debug[0])
    assert pogo.signature == lief.PE.Pogo.SIGNATURES.ZERO
    assert len(pogo.entries) == 55

    assert isinstance(sample.debug[1], lief.PE.Repro)
    repro = cast(lief.PE.Repro, sample.debug[1])
    assert repro.type == lief.PE.Debug.TYPES.REPRO
    assert repro.copy() == repro
    assert bytes(repro.hash).hex() == "09ba3f4077f89b528d07513e6c58d0b0fb10aacb9add786f79b2265695da5ebe"
    print(repro)
    json_view = json.loads(lief.to_json(repro))
    assert json_view == {
        "addressof_rawdata": 157856,
        "characteristics": 0,
        "hash": [9, 186, 63, 64, 119, 248, 155, 82, 141, 7, 81, 62, 108, 88, 208, 176, 251, 16, 170, 203, 154, 221, 120, 111, 121, 178, 38, 86, 149, 218, 94, 190],
        "major_version": 0,
        "minor_version": 0,
        "pointerto_rawdata": 153760,
        "sizeof_data": 36,
        "timestamp": 3193887381,
        "type": "REPRO"
    }

    assert sample.is_reproducible_build

def test_overlay_dbg():
    # Debug info can be located in the 'overlay' area.
    # Make sure we can process them
    input_path = get_sample("PE/sqlwid.dll")
    pe = lief.PE.parse(input_path)

    assert len(pe.debug) == 1

    cv: lief.PE.CodeView = pe.debug[0]
    assert isinstance(cv, lief.PE.CodeView)
    assert cv.cv_signature == lief.PE.CodeView.SIGNATURES.PDB_20
    assert isinstance(cv, lief.PE.CodeViewPDB)
    assert cv.filename == "sqlwid.pdb"

def test_pdbchecksum(tmp_path: Path):
    input_path = Path(get_sample("PE/WinStore.Instrumentation.dll"))
    pe = lief.PE.parse(input_path)

    pdbchecksum: lief.PE.PDBChecksum = pe.debug[1]
    assert isinstance(pdbchecksum, lief.PE.PDBChecksum)

    assert bytes(pdbchecksum.hash).hex(":") == "a0:d9:eb:9c:15:9f:77:2f:27:a5:84:b2:a6:a9:b7:a5:58:5c:ca:af:4d:9d:9a:d5:17:b1:bd:7c:62:fb:cd:73"
    assert pdbchecksum.algorithm == lief.PE.PDBChecksum.HASH_ALGO.SHA256

    pdbchecksum.hash = [1] * len(pdbchecksum.hash)

    output_path = tmp_path / input_path.name
    pe.write(output_path.as_posix())

    new_pe = lief.PE.parse(output_path)
    pdbchecksum: lief.PE.PDBChecksum = new_pe.debug[1]
    assert list(pdbchecksum.hash) == [1] * len(pdbchecksum.hash)

def test_empty_repro():
    input_path = get_sample("PE/WinStore.Instrumentation.dll")
    pe = lief.PE.parse(input_path)

    assert len(pe.debug) == 3
    for d in pe.debug:
        print(d)

    assert pe.debug[2].type == lief.PE.Debug.TYPES.REPRO


def test_vc_features(tmp_path: Path):
    """
    According to link.exe /dump:
        Counts: Pre-VC++ 11.00=0, C/C++=33, /GS=33, /sdl=2, guardN=31
    """
    input_path = Path(get_sample("PE/PE32_x86_binary_HelloWorld.exe"))
    pe = lief.PE.parse(input_path)
    vcfeat: lief.PE.VCFeature = pe.debug[1]

    assert isinstance(vcfeat, lief.PE.VCFeature)

    assert str(vcfeat) == dedent("""\
    Characteristics:     0x0
    Timestamp:           0x59047153
    Major/Minor version: 0.0
    Type:                VC_FEATURE
    Size of data:        0x14
    Address of rawdata:  0x2254
    Pointer to rawdata:  0x1454
      Counts: Pre-VC++ 11.00=0, C/C++=33, /GS=33, /sdl=2, guardN=31""")

    assert vcfeat.pre_vcpp == 0
    assert vcfeat.c_cpp == 33
    assert vcfeat.gs == 33
    assert vcfeat.guards == 31

    vcfeat.gs = 39
    output_path = tmp_path / input_path.name
    pe.write(output_path.as_posix())

    new_pe = lief.PE.parse(output_path)
    vcfeat: lief.PE.VCFeature = new_pe.debug[1]
    assert vcfeat.gs == 39


def test_ex_dll_characteristics(tmp_path: Path):
    input_path = Path(get_sample("PE/arm64x_ImagingEngine.dll"))
    pe = lief.PE.parse(input_path)
    entry: lief.PE.ExDllCharacteristics = pe.debug[3]
    assert isinstance(entry, lief.PE.ExDllCharacteristics)
    assert str(entry) == dedent("""\
    Characteristics:     0x0
    Timestamp:           0x9aa794d9
    Major/Minor version: 0.0
    Type:                EX_DLLCHARACTERISTICS
    Size of data:        0x4
    Address of rawdata:  0x33073c
    Pointer to rawdata:  0x32e13c
      Characteristics: HOTPATCH_COMPATIBLE""")
    assert entry.has(lief.PE.ExDllCharacteristics.CHARACTERISTICS.HOTPATCH_COMPATIBLE)
    assert not entry.has(lief.PE.ExDllCharacteristics.CHARACTERISTICS.CET_COMPAT_STRICT_MODE)
    assert entry.ex_characteristics == lief.PE.ExDllCharacteristics.CHARACTERISTICS.HOTPATCH_COMPATIBLE
    assert entry.ex_characteristics_list == [lief.PE.ExDllCharacteristics.CHARACTERISTICS.HOTPATCH_COMPATIBLE]

    entry.characteristics = (
        lief.PE.ExDllCharacteristics.CHARACTERISTICS.CET_COMPAT |
        lief.PE.ExDllCharacteristics.CHARACTERISTICS.HOTPATCH_COMPATIBLE
    )
    output_path = tmp_path / input_path.name
    pe.write(output_path.as_posix())

    new_pe = lief.PE.parse(output_path)
    entry: lief.PE.ExDllCharacteristics = new_pe.debug[3]
    assert entry.characteristics == (
        lief.PE.ExDllCharacteristics.CHARACTERISTICS.HOTPATCH_COMPATIBLE |
        lief.PE.ExDllCharacteristics.CHARACTERISTICS.CET_COMPAT
    )

def test_fpo(tmp_path: Path):
    input_path = Path(get_sample("PE/chnginbx.exe"))
    pe = lief.PE.parse(input_path)
    fpo: lief.PE.FPO = pe.debug[1]

    assert isinstance(fpo, lief.PE.FPO)
    assert len(fpo.entries) == 247
    assert fpo.entries[0].rva == 0x00001fc0
    assert fpo.entries[0].proc_size == 283
    assert fpo.entries[0].nb_locals == 28
    assert fpo.entries[0].nb_saved_regs == 3
    assert fpo.entries[0].prolog_size == 283
    assert fpo.entries[0].use_bp
    assert not fpo.entries[0].use_seh
    assert fpo.entries[0].type == lief.PE.FPO.FRAME_TYPE.NON_FPO
    assert fpo.entries[0].parameters_size == 0

    assert fpo.entries[246].rva == 0x0000f820
    assert fpo.entries[246].proc_size == 329
    assert fpo.entries[246].nb_locals == 0
    assert fpo.entries[246].nb_saved_regs == 2
    assert fpo.entries[246].prolog_size == 329
    assert not fpo.entries[246].use_bp
    assert not fpo.entries[246].use_seh
    assert fpo.entries[246].type == lief.PE.FPO.FRAME_TYPE.FPO
    assert fpo.entries[246].parameters_size == 8

    output_path = tmp_path / input_path.name
    pe.write(output_path.as_posix())

    new_pe = lief.PE.parse(output_path)
    fpo: lief.PE.FPO = new_pe.debug[1]
    assert len(fpo.entries) == 247
