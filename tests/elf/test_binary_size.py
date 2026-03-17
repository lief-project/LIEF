import lief
import pathlib
from utils import get_sample, check_layout

def test_builder_size():
    FILES = [
        "ELF/batch-x86-64/test.clang.fcf_protection.bin",
        "ELF/batch-x86-64/test.clang.fcf_protection.nopie.bin",
        "ELF/batch-x86-64/test.clang.fullstatic.nothread.bin",
    ]
    for file in FILES:
        infile = pathlib.Path(get_sample(file))
        target = lief.ELF.parse(infile)
        config = lief.ELF.Builder.config_t()
        config.notes = False

        raw = target.write_to_bytes(config)
        assert len(raw) <= infile.stat().st_size

        new = lief.ELF.parse(raw)
        check_layout(new)
