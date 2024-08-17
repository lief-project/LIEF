import lief
import pytest

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

def test_itanium():
    assert lief.demangle("_ZN8nanobind6detail16type_caster_baseIN4LIEF3DEX6HeaderEEcvRS4_Ev") == "nanobind::detail::type_caster_base<LIEF::DEX::Header>::operator LIEF::DEX::Header&()"

def test_rust():
    assert lief.demangle("_RNvCskwGfYPst2Cb_3foo16example_function") == "foo::example_function"

def test_ms():
    assert lief.demangle("??_C@_0CC@KGNKJKHE@heap_failure_listentry_corruptio@FNODOBFM@") == '"heap_failure_listentry_corruptio"...'
