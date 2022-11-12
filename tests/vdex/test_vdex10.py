import lief
import json
from utils import get_sample
from pathlib import Path

CWD = Path(__file__).parent

def test_vdex10():
    telecom = lief.VDEX.parse(get_sample('VDEX/VDEX_10_AArch64_Telecom.vdex'))

    # 1 Dex File registred
    assert len(telecom.dex_files) == 1

    dex_file = telecom.dex_files[0]
    dex2dex_json_info_lhs = json.loads(dex_file.dex2dex_json_info)

    json_test_path = CWD / "VDEX_10_AArch64_Telecom_quickinfo.json"

    dex2dex_json_info_rhs = None

    with open(json_test_path, 'r') as f:
        dex2dex_json_info_rhs = json.load(f)
    assert dex2dex_json_info_lhs == dex2dex_json_info_rhs

def test_header():
    telecom = lief.VDEX.parse(get_sample('VDEX/VDEX_10_AArch64_Telecom.vdex'))
    header = telecom.header

    assert header.magic == [118, 100, 101, 120]
    assert header.version == 10
    assert header.nb_dex_files == 1
    assert header.dex_size == 1421904
    assert header.quickening_info_size == 584
    assert header.verifier_deps_size == 18988


def test_dex_files():
    telecom = lief.VDEX.parse(get_sample('VDEX/VDEX_10_AArch64_Telecom.vdex'))
    h           = hash(telecom.dex_files[0])
    h_file      = lief.hash(telecom.dex_files[0].raw(False))
    h_file_dopt = lief.hash(telecom.dex_files[0].raw(True))

    #assert h == 4434625889427456908
    #assert h_file == 18446744071715884987
    #assert h_file_dopt == 18446744072171126186
