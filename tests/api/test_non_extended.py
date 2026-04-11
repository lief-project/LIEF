import lief
import pytest
from utils import get_sample, parse_elf

if lief.__extended__:
    pytest.skip("skipping: non-extended version only", allow_module_level=True)


def test_debug_info(capsys):
    elf = parse_elf("ELF/simple-gcc-c.bin")
    info = elf.debug_info
    assert info is None
    captured = capsys.readouterr()
    assert captured.err.startswith("Debug info not available for this build")

    pdb = lief.pdb.load(get_sample("PDB/libobjc2.pdb"))
    assert pdb is None
    captured = capsys.readouterr()
    assert captured.err.startswith("Debug info not available for this build")

    pdb = lief.pdb.DebugInfo.from_file(get_sample("PDB/libobjc2.pdb"))
    assert pdb is None
    captured = capsys.readouterr()
    assert captured.err.startswith("Debug info not available for this build")
