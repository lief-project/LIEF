import os
from pathlib import Path
from itertools import chain
from subprocess import check_call

from utils import lief_samples_dir

samples_dir = Path(lief_samples_dir())
macho_samples = chain(
    samples_dir.glob("PE/*.bin"),
    samples_dir.glob("PE/*.dylib"),
)

BUILD_DIR = os.getenv("LIEF_BUILD_DIR", None)

assert BUILD_DIR is not None

BUILD_DIR = Path(BUILD_DIR)

def test_macho_reader_c():
    target = BUILD_DIR / "examples" / "c" / "macho_reader"
    for sample in macho_samples:
        check_call([target, sample])

def test_macho_reader_cpp():
    target = BUILD_DIR / "examples" / "cpp" / "macho_reader"
    for sample in macho_samples:
        check_call([target, sample])

def test_abstract_reader():
    target = BUILD_DIR / "examples" / "cpp" / "abstract_reader"
    for sample in macho_samples:
        check_call([target, sample])
