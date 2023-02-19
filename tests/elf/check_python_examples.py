import pytest
import sys
from pathlib import Path
from subprocess import check_call

from utils import lief_samples_dir

samples_dir = Path(lief_samples_dir())

LIEF_PY_DIR = Path(__file__).parent / ".." / ".." / "api" / "python" / "examples"

@pytest.mark.parametrize("elf", [
    "ELF/ELF32_x86_binary_ls.bin",
    "ELF/ELF32_ARM_binary_ls.bin",
])
def test_elf_reader(elf):
    sample = samples_dir / Path(elf)
    target = LIEF_PY_DIR / "elf_reader.py"
    check_call([sys.executable, target, "--all", sample])

@pytest.mark.parametrize("elf", [
    "ELF/ELF32_x86_binary_ls.bin",
])
def test_elf_remove_section_table(tmp_path: Path, elf):
    out = tmp_path / "out.bin"
    sample = samples_dir / Path(elf)
    target = LIEF_PY_DIR / "elf_remove_section_table.py"
    check_call([sys.executable, target, sample, out])

@pytest.mark.parametrize("elf", [
    "ELF/ELF32_x86_binary_ls.bin",
])
def test_elf_symbol_obfuscation(tmp_path: Path, elf):
    out = tmp_path / "out.bin"
    sample = samples_dir / Path(elf)
    target = LIEF_PY_DIR / "elf_symbol_obfuscation.py"
    check_call([sys.executable, target, sample, out])

@pytest.mark.parametrize("elf", [
    "ELF/ELF64_x86-64_binary_ls.bin",
])
def test_elf_unstrip(tmp_path: Path, elf):
    out = tmp_path / "out.bin"
    sample = samples_dir / Path(elf)
    target = LIEF_PY_DIR / "elf_unstrip.py"
    check_call([sys.executable, target, sample, out])

@pytest.mark.parametrize("elf", [
    "ELF/ELF64_x86-64_binary_ls.bin",
])
def test_elf_json(elf):
    sample = samples_dir / Path(elf)
    target = LIEF_PY_DIR / "elf_json.py"
    check_call([sys.executable, target, sample])
