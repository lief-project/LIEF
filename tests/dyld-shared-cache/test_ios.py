from pathlib import Path

import lief
import pytest
from utils import get_dsc_sample, has_dyld_shared_cache_samples

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

if not has_dyld_shared_cache_samples():
    pytest.skip("skipping: missing dyld shared cache files", allow_module_level=True)


def test_ios_18():
    dsc = lief.dsc.load(get_dsc_sample("ios-18.1"))
    assert dsc is not None
    assert dsc.filename == "dyld_shared_cache_arm64e"
    assert dsc.version == lief.dsc.DyldSharedCache.VERSION.DYLD_1231_3
    assert dsc.load_address == 0x180000000
    assert dsc.arch == lief.dsc.DyldSharedCache.ARCH.ARM64E
    assert dsc.platform == lief.dsc.DyldSharedCache.PLATFORM.IOS
    assert dsc.arch_name == "arm64e"

    assert dsc.find_lib_from_va(0) is None
    _lib_va = dsc.find_lib_from_va(0x20D0A4010)
    assert _lib_va is not None
    assert _lib_va.path == "/System/Library/Frameworks/OpenGLES.framework/OpenGLES"
    assert dsc.find_lib_from_path("/usr/lib/libobjc.A.dylib") is not None
    assert dsc.find_lib_from_path("/usr/lib/libobjc.X.dylib") is None

    assert dsc.find_lib_from_name("liblockdown.dylib") is not None
    assert dsc.find_lib_from_name("liblockdown.Y.dylib") is None

    assert Path(dsc.filepath).as_posix().endswith("ios-18.1/dyld_shared_cache_arm64e")
    assert lief.is_shared_cache(Path(dsc.filepath))

    libraries = dsc.libraries

    assert len(libraries) == 3756
    _lib0 = libraries[0]
    assert _lib0 is not None
    assert _lib0.path == "/usr/lib/libobjc.A.dylib"
    assert _lib0.inode == 0
    assert _lib0.address == 0x180100000
    assert _lib0.modtime == 0
    assert _lib0.padding == 0

    _lib900 = libraries[900]
    assert _lib900 is not None
    assert _lib900.path == "/System/Library/Frameworks/OpenGLES.framework/OpenGLES"
    assert _lib900.inode == 0
    assert _lib900.address == 0x20D0A4000
    assert _lib900.modtime == 0
    assert _lib900.padding == 0

    map_info = dsc.mapping_info
    assert len(map_info) == 1
    _mi0 = map_info[0]
    assert _mi0 is not None
    assert _mi0.address == 0x180000000
    assert _mi0.size == 0x80000
    assert _mi0.end_address == 0x180080000
    assert _mi0.file_offset == 0
    assert _mi0.max_prot == 5
    assert _mi0.init_prot == 5

    assert dsc.has_subcaches
    subcaches = dsc.subcaches

    assert len(subcaches) == 62
    _sc0 = subcaches[0]
    assert _sc0 is not None
    assert _sc0.suffix == ".01"
    assert _sc0.vm_offset == 0x80000
    _sc0_cache = _sc0.cache
    assert _sc0_cache is not None
    assert _sc0_cache.filename == "dyld_shared_cache_arm64e.01"
    assert (
        bytes(_sc0.uuid).hex(":") == "9e:52:2b:55:1d:d4:33:c3:b1:b1:2b:88:a8:a3:99:28"
    )
    assert str(_sc0)
