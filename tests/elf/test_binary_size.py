import pathlib

import lief
from utils import check_layout, get_sample


def test_builder_size():
    FILES = [
        "ELF/batch-x86-64/test.clang.fcf_protection.bin",
        "ELF/batch-x86-64/test.clang.fcf_protection.nopie.bin",
        "ELF/batch-x86-64/test.clang.fullstatic.nothread.bin",
    ]
    for file in FILES:
        infile = pathlib.Path(get_sample(file))
        target = lief.ELF.parse(infile)
        assert target is not None
        config = lief.ELF.Builder.config_t()
        config.notes = False

        raw = target.write_to_bytes(config)
        assert len(raw) <= infile.stat().st_size

        new = lief.ELF.parse(raw)
        check_layout(new)
