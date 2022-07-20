import pytest

import lief
import pathlib

from utils import get_sample

def test_issue_749():
    lib_path = get_sample('ELF/lib_symbol_versions.so')
    lib: lief.ELF.Binary = lief.parse(lib_path)
    sym = lib.get_dynamic_symbol("foo")
    assert sym.symbol_version.symbol_version_auxiliary.name == "LIBFOO_2.0"



