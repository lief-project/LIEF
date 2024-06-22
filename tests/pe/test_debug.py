import lief
import json
from utils import get_sample
from typing import cast

def test_pgo():
    path   = get_sample("PE/PE32_x86_binary_PGO-LTCG.exe")
    sample = lief.PE.parse(path)

    debugs = sample.debug
    assert len(debugs) == 3
    assert debugs[0].type == lief.PE.Debug.TYPES.CODEVIEW
    assert debugs[1].type == lief.PE.Debug.TYPES.VC_FEATURE
    assert debugs[2].type == lief.PE.Debug.TYPES.POGO

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
    cv: lief.PE.CodeViewPDB = sample.codeview_pdb
    assert cv is not None
    assert cv.guid == "fcb9afc6-a352-f97b-17cf-5f981382c782"

    path = get_sample('PE/PE64_x86-64_binary_ConsoleApplication1.exe')
    sample = lief.PE.parse(path)
    cv: lief.PE.CodeViewPDB = sample.codeview_pdb
    assert cv is not None
    assert cv.guid == "b6e3d9f5-7147-4f01-a203-aa477c4aba54"

def test_code_view_pdb():
    path = get_sample('PE/PE64_x86-64_binary_ConsoleApplication1.exe')
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
