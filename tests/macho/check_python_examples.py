import pytest
import sys
from pathlib import Path

from utils import lief_samples_dir, import_from_file

samples_dir = Path(lief_samples_dir())

LIEF_PY_DIR = Path(__file__).parent / ".." / ".." / "api" / "python" / "examples"

@pytest.mark.parametrize("macho", [
    "MachO/MachO64_x86-64_binary_ls.bin",
    "MachO/FAT_MachO_x86_x86-64_library_libc.dylib",
])
def test_macho_reader(monkeypatch, macho):
    sample = samples_dir / Path(macho)
    target = LIEF_PY_DIR / "macho_reader.py"
    macho_reader = import_from_file("macho_reader", target)
    with monkeypatch.context() as m:
        m.setattr(sys, "argv", [target.name, "--all", sample.as_posix()])
        macho_reader.main()
