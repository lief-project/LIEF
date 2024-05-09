import lief
from pathlib import Path
from utils import get_sample

import hashlib

def test_code_signature():
    bin_path = Path(get_sample('MachO/MachO64_x86-64_binary_id.bin'))
    original: lief.MachO.Binary = lief.MachO.parse(bin_path.as_posix()).at(0)

    assert original[lief.MachO.LoadCommand.TYPE.CODE_SIGNATURE] is not None
    code_signature: lief.MachO.CodeSignature = original[lief.MachO.LoadCommand.TYPE.CODE_SIGNATURE] # type: ignore[assignment]
    assert hashlib.sha256(bytes(code_signature.content)).hexdigest() == "3aadc3f197fd6642b31aea9c5e09dbb021360224cd60292d6039515f24f5dbdb"

    assert hash(code_signature) > 0

def test_code_signature_dir():
    bin_path = Path(get_sample('MachO/python3_issue_476.bin'))
    python3: lief.MachO.Binary = lief.MachO.parse(bin_path.as_posix()).at(0)

    assert python3[lief.MachO.LoadCommand.TYPE.DYLIB_CODE_SIGN_DRS] is not None
    code_signature_dirs: lief.MachO.CodeSignatureDir = python3[lief.MachO.LoadCommand.TYPE.DYLIB_CODE_SIGN_DRS] # type: ignore[assignment]
    assert hashlib.sha256(bytes(code_signature_dirs.content)).hexdigest() == "6e14d00dd2e6b2a85d355db52e1e9614b07e04ec563bb638f2474b52dacabc22"

    assert hash(code_signature_dirs) > 0
    #lief.MachO.LoadCommand.TYPE.LINKER_OPTIMIZATION_HINT
