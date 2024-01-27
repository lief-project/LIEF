import pytest

import lief
from pathlib import Path

from utils import get_sample

def test_issue_749():
    lib_path = get_sample('ELF/lib_symbol_versions.so')
    lib: lief.ELF.Binary = lief.parse(lib_path)
    sym = lib.get_dynamic_symbol("foo")
    assert sym.symbol_version.symbol_version_auxiliary.name == "LIBFOO_2.0"

def test_issue_1014(tmp_path: Path):
    lib_path = get_sample('ELF/libfoo_issue_1014.so')
    lib: lief.ELF.Binary = lief.parse(lib_path)
    def check_lib(lib: lief.ELF.Binary):
        svd = lib.symbols_version_definition
        assert len(svd) == 6

        assert len(svd[0].auxiliary_symbols) == 1
        assert svd[0].auxiliary_symbols[0].name == "libfoo.so"

        assert len(svd[1].auxiliary_symbols) == 1
        assert svd[1].auxiliary_symbols[0].name == "LIBFOO_1.0"

        assert len(svd[2].auxiliary_symbols) == 2
        assert svd[2].auxiliary_symbols[0].name == "LIBFOO_2.0"
        assert svd[2].auxiliary_symbols[1].name == "LIBFOO_1.0"

        assert len(svd[3].auxiliary_symbols) == 2
        assert svd[3].auxiliary_symbols[0].name == "LIBFOO_3.0"
        assert svd[3].auxiliary_symbols[1].name == "LIBFOO_2.0"

        assert len(svd[4].auxiliary_symbols) == 1
        assert svd[4].auxiliary_symbols[0].name == "LIBBAR_1.0"

        assert len(svd[5].auxiliary_symbols) == 2
        assert svd[5].auxiliary_symbols[0].name == "LIBBAR_2.0"
        assert svd[5].auxiliary_symbols[1].name == "LIBBAR_1.0"
    check_lib(lib)

    out = tmp_path / "libfoo_issue_1014.so"
    lib.write(out.as_posix())
    new_lib = lief.ELF.parse(out.as_posix())
    check_lib(new_lib)
