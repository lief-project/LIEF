import hashlib
from pathlib import Path
from typing import cast

import lief
from utils import get_sample


def test_code_signature():
    bin_path = Path(get_sample("MachO/MachO64_x86-64_binary_id.bin"))
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    original = fat.at(0)
    assert original is not None

    assert original[lief.MachO.LoadCommand.TYPE.CODE_SIGNATURE] is not None
    code_signature = cast(
        lief.MachO.CodeSignature, original[lief.MachO.LoadCommand.TYPE.CODE_SIGNATURE]
    )
    assert (
        hashlib.sha256(bytes(code_signature.content)).hexdigest()
        == "3aadc3f197fd6642b31aea9c5e09dbb021360224cd60292d6039515f24f5dbdb"
    )

    assert hash(code_signature) > 0


def test_code_signature_dir():
    bin_path = Path(get_sample("MachO/python3_issue_476.bin"))
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    python3 = fat.at(0)
    assert python3 is not None

    assert python3[lief.MachO.LoadCommand.TYPE.DYLIB_CODE_SIGN_DRS] is not None
    code_signature_dirs = cast(
        lief.MachO.CodeSignatureDir,
        python3[lief.MachO.LoadCommand.TYPE.DYLIB_CODE_SIGN_DRS],
    )
    assert (
        hashlib.sha256(bytes(code_signature_dirs.content)).hexdigest()
        == "6e14d00dd2e6b2a85d355db52e1e9614b07e04ec563bb638f2474b52dacabc22"
    )

    assert hash(code_signature_dirs) > 0
    # lief.MachO.LoadCommand.TYPE.LINKER_OPTIMIZATION_HINT
