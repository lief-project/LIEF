import sys
from pathlib import Path

import pytest
from pytest import MonkeyPatch
from utils import import_from_file, lief_samples_dir

samples_dir = Path(lief_samples_dir())

LIEF_PY_DIR = Path(__file__).parent / ".." / ".." / "api" / "python" / "examples"


@pytest.mark.parametrize(
    "elf",
    [
        "ELF/ELF32_x86_binary_ls.bin",
        "ELF/ELF32_ARM_binary_ls.bin",
    ],
)
def test_elf_reader(monkeypatch: MonkeyPatch, elf: str) -> None:
    sample = samples_dir / Path(elf)
    target = LIEF_PY_DIR / "elf_reader.py"
    elf_reader = import_from_file("elf_reader", target)
    with monkeypatch.context() as m:
        m.setattr(sys, "argv", [target.name, "--all", sample.as_posix()])
        elf_reader.main()


@pytest.mark.parametrize(
    "elf",
    [
        "ELF/ELF32_x86_binary_ls.bin",
    ],
)
def test_elf_remove_section_table(
    monkeypatch: MonkeyPatch, tmp_path: Path, elf: str
) -> None:
    out = tmp_path / "out.bin"
    sample = samples_dir / Path(elf)
    target = LIEF_PY_DIR / "elf_remove_section_table.py"

    module = import_from_file("elf_remove_section_table", target)
    with monkeypatch.context() as m:
        m.setattr(sys, "argv", [target.name, sample.as_posix(), out.as_posix()])
        module.main()


@pytest.mark.parametrize(
    "elf",
    [
        "ELF/ELF32_x86_binary_ls.bin",
    ],
)
def test_elf_symbol_obfuscation(
    monkeypatch: MonkeyPatch, tmp_path: Path, elf: str
) -> None:
    out = tmp_path / "out.bin"
    sample = samples_dir / Path(elf)
    target = LIEF_PY_DIR / "elf_symbol_obfuscation.py"
    module = import_from_file("elf_symbol_obfuscation", target)
    with monkeypatch.context() as m:
        m.setattr(sys, "argv", [target.name, sample.as_posix(), out.as_posix()])
        module.main()


@pytest.mark.parametrize(
    "elf",
    [
        "ELF/ELF64_x86-64_binary_ls.bin",
    ],
)
def test_elf_unstrip(monkeypatch: MonkeyPatch, tmp_path: Path, elf: str) -> None:
    out = tmp_path / "out.bin"
    sample = samples_dir / Path(elf)
    target = LIEF_PY_DIR / "elf_unstrip.py"

    module = import_from_file("elf_unstrip", target)
    with monkeypatch.context() as m:
        m.setattr(sys, "argv", [target.name, sample.as_posix(), out.as_posix()])
        module.main()


@pytest.mark.parametrize(
    "elf",
    [
        "ELF/ELF64_x86-64_binary_all.bin",
    ],
)
def test_elf_bin2lib(monkeypatch: MonkeyPatch, tmp_path: Path, elf: str) -> None:
    out = tmp_path / "libfoo.so"
    sample = samples_dir / Path(elf)
    target = LIEF_PY_DIR / "elf_bin2lib.py"
    module = import_from_file("elf_bin2lib", target)
    with monkeypatch.context() as m:
        m.setattr(
            sys,
            "argv",
            [target.name, "--output", out.as_posix(), sample.as_posix(), "0x960"],
        )
        module.main()


@pytest.mark.parametrize(
    "elf",
    [
        "ELF/ELF64_x86-64_binary_ls.bin",
    ],
)
def test_elf_json(monkeypatch: MonkeyPatch, elf: str) -> None:
    sample = samples_dir / Path(elf)
    target = LIEF_PY_DIR / "elf_json.py"
    module = import_from_file("elf_json", target)
    with monkeypatch.context() as m:
        m.setattr(sys, "argv", [target.name, sample.as_posix()])
        module.main()
