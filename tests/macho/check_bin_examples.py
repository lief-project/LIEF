from pathlib import Path
from subprocess import check_call

from utils import lief_build_dir, lief_samples_dir

SAMPLE = lief_samples_dir() / "MachO" / "MachO64_x86-64_binary_ls.bin"


def test_macho_reader_c() -> None:
    target = lief_build_dir() / "examples/c/macho_reader"
    check_call([target, SAMPLE])


def test_macho_reader_cpp() -> None:
    target = lief_build_dir() / "examples/cpp/macho_reader"
    check_call([target, SAMPLE])


def test_abstract_reader() -> None:
    target = lief_build_dir() / "examples/cpp/abstract_reader"
    check_call([target, SAMPLE])


def test_macho_builder(tmp_path: Path) -> None:
    out = tmp_path / "out.bin"
    target = lief_build_dir() / "examples/cpp/macho_builder"
    check_call([target, SAMPLE, out])
