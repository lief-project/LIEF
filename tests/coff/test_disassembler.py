import lief
import pytest
from utils import parse_coff

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)


def test_simple():
    coff = parse_coff("COFF/disa_test.obj")

    _bar = coff.find_demangled_function("int __cdecl bar(int, int)")
    assert _bar is not None
    assert _bar.value == 0
    _foo = coff.find_function("?foo@@YAHHH@Z")
    assert _foo is not None
    assert _foo.value == 32

    assert (
        str(next(coff.disassemble("?foo@@YAHHH@Z")))
        == "0x000020: mov dword ptr [rsp + 16], edx"
    )
    assert (
        str(next(coff.disassemble("int __cdecl bar(int, int)")))
        == "0x000000: mov dword ptr [rsp + 16], edx"
    )
    main_disa = list(coff.disassemble("main"))

    assert len(main_disa) == 11
    assert str(main_disa[9]) == "0x000065: add rsp, 40"
