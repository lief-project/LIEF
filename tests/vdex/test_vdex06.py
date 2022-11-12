import lief
import json
from pathlib import Path
from utils import get_sample

CWD = Path(__file__).parent

def test_vdex06():
    telecom = lief.VDEX.parse(get_sample('VDEX/VDEX_06_AArch64_Telecom.vdex'))

    # 1 Dex File registred
    assert len(telecom.dex_files) == 1

    dex_file = telecom.dex_files[0]

    dex2dex_json_info_lhs = json.loads(dex_file.dex2dex_json_info)

    json_test_path = CWD / "VDEX_06_AArch64_Telecom_quickinfo.json"
    dex2dex_json_info_rhs = None
    with open(json_test_path, 'r') as f:
        dex2dex_json_info_rhs = json.load(f)

    assert dex2dex_json_info_lhs == dex2dex_json_info_rhs

def test_header():
    telecom = lief.VDEX.parse(get_sample('VDEX/VDEX_06_AArch64_Telecom.vdex'))
    header = telecom.header

    assert header.magic == [118, 100, 101, 120]
    assert header.version == 6
    assert header.nb_dex_files == 1
    assert header.dex_size == 940500
    assert header.quickening_info_size == 18104
    assert header.verifier_deps_size == 11580

def test_dex_files():
    telecom = lief.VDEX.parse(get_sample('VDEX/VDEX_06_AArch64_Telecom.vdex'))
    h           = hash(telecom.dex_files[0])
    h_file      = lief.hash(telecom.dex_files[0].raw(False))
    h_file_dopt = lief.hash(telecom.dex_files[0].raw(True))
