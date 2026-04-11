from functools import lru_cache
from itertools import chain
from subprocess import check_call

from utils import lief_build_dir, lief_samples_dir


@lru_cache(maxsize=1)
def _get_samples():
    samples_dir = lief_samples_dir()
    return chain(
        samples_dir.glob("PE/*.exe"),
        samples_dir.glob("PE/*.dll"),
    )


def test_pe_reader_c():
    target = lief_build_dir() / "examples/c/pe_reader"
    for sample in _get_samples():
        check_call([target, sample])


def test_pe_reader_cpp():
    target = lief_build_dir() / "examples/cpp/pe_reader"
    for sample in _get_samples():
        check_call([target, sample])


def test_abstract_reader():
    target = lief_build_dir() / "examples/cpp/abstract_reader"
    for sample in _get_samples():
        check_call([target, sample])
