import pytest
import sys
from pathlib import Path

from utils import lief_samples_dir, import_from_file

samples_dir = Path(lief_samples_dir())

LIEF_PY_DIR = Path(__file__).parent / ".." / ".." / "api" / "python" / "examples"

@pytest.mark.parametrize("elf", [
    "ELF/ELF32_x86_binary_ls.bin",
    "ELF/ELF32_ARM_binary_ls.bin",
])
def test_elf_reader(monkeypatch, elf):
    sample = samples_dir / Path(elf)
    target = LIEF_PY_DIR / "elf_reader.py"
    elf_reader = import_from_file("elf_reader", target)
    with monkeypatch.context() as m:
        m.setattr(sys, "argv", [target.name, "--all", sample.as_posix()])
        elf_reader.main()

@pytest.mark.parametrize("elf", [
    "ELF/ELF32_x86_binary_ls.bin",
])
def test_elf_remove_section_table(monkeypatch, tmp_path: Path, elf):
    out = tmp_path / "out.bin"
    sample = samples_dir / Path(elf)
    target = LIEF_PY_DIR / "elf_remove_section_table.py"

    module = import_from_file("elf_remove_section_table", target)
    with monkeypatch.context() as m:
        m.setattr(sys, "argv", [target.name, sample.as_posix(), out.as_posix()])
        module.main()

@pytest.mark.parametrize("elf", [
    "ELF/ELF32_x86_binary_ls.bin",
])
def test_elf_symbol_obfuscation(monkeypatch, tmp_path: Path, elf):
    out = tmp_path / "out.bin"
    sample = samples_dir / Path(elf)
    target = LIEF_PY_DIR / "elf_symbol_obfuscation.py"
    module = import_from_file("elf_symbol_obfuscation", target)
    with monkeypatch.context() as m:
        m.setattr(sys, "argv", [target.name, sample.as_posix(), out.as_posix()])
        module.main()

@pytest.mark.parametrize("elf", [
    "ELF/ELF64_x86-64_binary_ls.bin",
])
def test_elf_unstrip(monkeypatch, tmp_path: Path, elf):
    out = tmp_path / "out.bin"
    sample = samples_dir / Path(elf)
    target = LIEF_PY_DIR / "elf_unstrip.py"

    module = import_from_file("elf_unstrip", target)
    with monkeypatch.context() as m:
        m.setattr(sys, "argv", [target.name, sample.as_posix(), out.as_posix()])
        module.main()

@pytest.mark.parametrize("elf", [
    "ELF/ELF64_x86-64_binary_ls.bin",
])
def test_elf_json(monkeypatch, elf):
    sample = samples_dir / Path(elf)
    target = LIEF_PY_DIR / "elf_json.py"
    module = import_from_file("elf_json", target)
    with monkeypatch.context() as m:
        m.setattr(sys, "argv", [target.name, sample.as_posix()])
        module.main()
