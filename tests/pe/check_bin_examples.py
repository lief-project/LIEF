import os
from pathlib import Path
from itertools import chain
from subprocess import check_call

from utils import lief_samples_dir

samples_dir = Path(lief_samples_dir())
pe_samples = chain(
    samples_dir.glob("PE/*.exe"),
    samples_dir.glob("PE/*.dll"),
)

BUILD_DIR = os.getenv("LIEF_BUILD_DIR", None)

assert BUILD_DIR is not None

BUILD_DIR = Path(BUILD_DIR)

def test_pe_reader_c():
    target = BUILD_DIR / "examples" / "c" / "pe_reader"
    for sample in pe_samples:
        check_call([target, sample])

def test_pe_reader_cpp():
    target = BUILD_DIR / "examples" / "cpp" / "pe_reader"
    for sample in pe_samples:
        check_call([target, sample])

def test_abstract_reader():
    target = BUILD_DIR / "examples" / "cpp" / "abstract_reader"
    for sample in pe_samples:
        check_call([target, sample])
