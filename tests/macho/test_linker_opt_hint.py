import lief
from pathlib import Path
from utils import get_sample

import hashlib

def test_simple():
    bin_path = Path(get_sample('MachO/json_api.cpp_1.o'))
    original: lief.MachO.Binary = lief.parse(bin_path.as_posix())

    assert original[lief.MachO.LoadCommand.TYPE.LINKER_OPTIMIZATION_HINT] is not None
    opthint: lief.MachO.LinkerOptHint = original[lief.MachO.LoadCommand.TYPE.LINKER_OPTIMIZATION_HINT]
    assert hashlib.sha256(bytes(opthint.content)).hexdigest() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    assert hash(opthint) > 0

