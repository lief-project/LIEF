from pathlib import Path
from subprocess import check_call

from utils import lief_build_dir, lief_samples_dir

SAMPLE = lief_samples_dir() / "PE" / "PE32_x86_library_kernel32.dll"


def test_pe_reader_c() -> None:
    target = lief_build_dir() / "examples/c/pe_reader"
    check_call([target, SAMPLE])


def test_pe_reader_cpp() -> None:
    target = lief_build_dir() / "examples/cpp/pe_reader"
    check_call([target, SAMPLE])


def test_abstract_reader() -> None:
    target = lief_build_dir() / "examples/cpp/abstract_reader"
    check_call([target, SAMPLE])


def test_pe_builder(tmp_path: Path) -> None:
    out = tmp_path / "out.dll"
    target = lief_build_dir() / "examples/cpp/pe_builder"
    check_call([target, SAMPLE, out])


def test_pe_authenticode_check() -> None:
    sample = (
        lief_samples_dir()
        / "PE"
        / "PE32_x86-64_binary_avast-free-antivirus-setup-online.exe"
    )
    target = lief_build_dir() / "examples/cpp/pe_authenticode_check"
    check_call([target, sample])
