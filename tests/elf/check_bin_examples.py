from functools import lru_cache
from itertools import chain
from pathlib import Path
from subprocess import check_call

from utils import lief_build_dir, lief_samples_dir


@lru_cache(maxsize=1)
def _get_samples():
    samples_dir = lief_samples_dir()
    return chain(
        samples_dir.glob("ELF/*.bin"),
        samples_dir.glob("ELF/*.so"),
        samples_dir.glob("ELF/*.pie"),
    )


def test_elf_reader_c():
    target = lief_build_dir() / "examples/c/elf_reader"
    for sample in _get_samples():
        check_call([target, sample])


def test_elf_reader_cpp():
    target = lief_build_dir() / "examples/cpp/elf_reader"
    for sample in _get_samples():
        check_call([target, sample])


def test_abstract_reader():
    target = lief_build_dir() / "examples/cpp/abstract_reader"
    for sample in _get_samples():
        check_call([target, sample])


def test_elf_strip(tmp_path: Path):
    out = tmp_path / "out.bin"
    target = lief_build_dir() / "examples/cpp/elf_strip"
    for sample in _get_samples():
        check_call([target, sample, out])


def test_elf_add_section(tmp_path: Path):
    out = tmp_path / "out.bin"
    target = lief_build_dir() / "examples/cpp/elf_add_section"
    for sample in _get_samples():
        check_call([target, sample, out])


def test_elf_symbols(tmp_path: Path):
    out = tmp_path / "out.bin"
    target = lief_build_dir() / "examples/cpp/elf_add_section"
    for sample in _get_samples():
        check_call([target, sample, out])
