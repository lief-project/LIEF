import os
from pathlib import Path
from itertools import chain
from subprocess import check_call

from utils import lief_samples_dir

samples_dir = Path(lief_samples_dir())
elf_samples = chain(
    samples_dir.glob("ELF/*.bin"),
    samples_dir.glob("ELF/*.so"),
    samples_dir.glob("ELF/*.pie"),
)

BUILD_DIR = os.getenv("LIEF_BUILD_DIR", None)

assert BUILD_DIR is not None

BUILD_DIR_PATH = Path(BUILD_DIR)

def test_elf_reader_c():
    target = BUILD_DIR_PATH / "examples" / "c" / "elf_reader"
    for sample in elf_samples:
        check_call([target, sample])

def test_elf_reader_cpp():
    target = BUILD_DIR_PATH / "examples" / "cpp" / "elf_reader"
    for sample in elf_samples:
        check_call([target, sample])

def test_abstract_reader():
    target = BUILD_DIR_PATH / "examples" / "cpp" / "abstract_reader"
    for sample in elf_samples:
        check_call([target, sample])

def test_elf_strip(tmp_path: Path):
    out = tmp_path / "out.bin"
    target = BUILD_DIR_PATH / "examples" / "cpp" / "elf_strip"
    for sample in elf_samples:
        check_call([target, sample, out])

def test_elf_add_section(tmp_path: Path):
    out = tmp_path / "out.bin"
    target = BUILD_DIR_PATH / "examples" / "cpp" / "elf_add_section"
    for sample in elf_samples:
        check_call([target, sample, out])

def test_elf_symbols(tmp_path: Path):
    out = tmp_path / "out.bin"
    target = BUILD_DIR_PATH / "examples" / "cpp" / "elf_add_section"
    for sample in elf_samples:
        check_call([target, sample, out])
