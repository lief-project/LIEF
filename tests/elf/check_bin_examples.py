from pathlib import Path
from subprocess import check_call

from utils import lief_build_dir, lief_samples_dir

SAMPLE = lief_samples_dir() / "ELF" / "ELF64_x86-64_binary_ls.bin"


def test_elf_reader_c() -> None:
    target = lief_build_dir() / "examples/c/elf_reader"
    check_call([target, SAMPLE])


def test_elf_reader_cpp() -> None:
    target = lief_build_dir() / "examples/cpp/elf_reader"
    check_call([target, SAMPLE])


def test_abstract_reader() -> None:
    target = lief_build_dir() / "examples/cpp/abstract_reader"
    check_call([target, SAMPLE])


def test_elf_strip(tmp_path: Path) -> None:
    out = tmp_path / "out.bin"
    target = lief_build_dir() / "examples/cpp/elf_strip"
    check_call([target, SAMPLE, out])


def test_elf_add_section(tmp_path: Path) -> None:
    out = tmp_path / "out.bin"
    target = lief_build_dir() / "examples/cpp/elf_add_section"
    check_call([target, SAMPLE, out])


def test_elf_symbols() -> None:
    target = lief_build_dir() / "examples/cpp/elf_symbols"
    check_call([target, SAMPLE])


def test_elf_section_rename(tmp_path: Path) -> None:
    out = tmp_path / "out.bin"
    target = lief_build_dir() / "examples/cpp/elf_section_rename"
    check_call([target, SAMPLE, out])


def test_elf_builder(tmp_path: Path) -> None:
    out = tmp_path / "out.bin"
    target = lief_build_dir() / "examples/cpp/elf_builder"
    check_call([target, SAMPLE, out])
