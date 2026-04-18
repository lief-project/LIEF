import hashlib
from pathlib import Path
from typing import cast

import lief
from utils import get_sample


def test_simple():
    bin_path = Path(get_sample("MachO/json_api.cpp_1.o"))
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    original = fat.at(0)
    assert original is not None

    assert original[lief.MachO.LoadCommand.TYPE.LINKER_OPTIMIZATION_HINT] is not None
    opthint = cast(
        lief.MachO.LinkerOptHint,
        original[lief.MachO.LoadCommand.TYPE.LINKER_OPTIMIZATION_HINT],
    )
    assert (
        hashlib.sha256(bytes(opthint.content)).hexdigest()
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    assert hash(opthint) > 0
    output = str(opthint)
    assert "offset" in output
