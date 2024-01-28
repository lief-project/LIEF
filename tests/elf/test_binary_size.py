import lief
import pathlib
from utils import get_sample

def test_builder_size():
    FILES = [
        "ELF/batch-x86-64/test.clang.fcf_protection.bin",
        "ELF/batch-x86-64/test.clang.fcf_protection.nopie.bin",
        "ELF/batch-x86-64/test.clang.fullstatic.nothread.bin",
    ]
    for file in FILES:
        infile = pathlib.Path(get_sample(file))
        target = lief.ELF.parse(infile.as_posix())
        print(infile)

        builder = lief.ELF.Builder(target)
        builder.config.notes = False
        builder.build()
        raw = builder.get_build()

        assert len(raw) <= infile.stat().st_size

