import lief
import pytest

from utils import has_dyld_shared_cache_samples, get_dsc_sample

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

if not has_dyld_shared_cache_samples():
    pytest.skip("skipping: missing dyld shared cache files", allow_module_level=True)

def test_filename():
    dsc = lief.dsc.load(get_dsc_sample("ios-18.1"))
    assert dsc is not None
    assert dsc.filename == "dyld_shared_cache_arm64e"

    dsc = lief.dsc.load(get_dsc_sample("ios-18.1/dyld_shared_cache_arm64e.62.dyldlinkedit"))
    assert dsc is not None
    assert dsc.filename == "dyld_shared_cache_arm64e.62.dyldlinkedit"
