import lief
import pytest
from pathlib import Path

from utils import has_dyld_shared_cache_samples, get_dsc_sample

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

if not has_dyld_shared_cache_samples():
    pytest.skip("skipping: missing dyld shared cache files", allow_module_level=True)

def test_ios_18():
    dsc = lief.dsc.load(get_dsc_sample("ios-18.1"))
    assert dsc is not None
    assert dsc.filename == "dyld_shared_cache_arm64e"
    assert dsc.version == lief.dsc.DyldSharedCache.VERSION.UNRELEASED
    assert dsc.load_address == 0x180000000
    assert dsc.arch == lief.dsc.DyldSharedCache.ARCH.ARM64E
    assert dsc.platform == lief.dsc.DyldSharedCache.PLATFORM.IOS
    assert dsc.arch_name == "arm64e"

    assert dsc.find_lib_from_va(0) is None
    assert dsc.find_lib_from_va(0x20d0a4010).path == "/System/Library/Frameworks/OpenGLES.framework/OpenGLES"
    assert dsc.find_lib_from_path("/usr/lib/libobjc.A.dylib") is not None
    assert dsc.find_lib_from_path("/usr/lib/libobjc.X.dylib") is None

    assert dsc.find_lib_from_name("liblockdown.dylib") is not None
    assert dsc.find_lib_from_name("liblockdown.Y.dylib") is None

    assert Path(dsc.filepath).as_posix().endswith("ios-18.1/dyld_shared_cache_arm64e")

    libraries = dsc.libraries

    assert len(libraries) == 3756
    assert libraries[0].path == "/usr/lib/libobjc.A.dylib"
    assert libraries[0].inode == 0
    assert libraries[0].address == 0x180100000
    assert libraries[0].modtime == 0
    assert libraries[0].padding == 0

    assert libraries[900].path == "/System/Library/Frameworks/OpenGLES.framework/OpenGLES"
    assert libraries[900].inode == 0
    assert libraries[900].address == 0x20d0a4000
    assert libraries[900].modtime == 0
    assert libraries[900].padding == 0

    map_info = dsc.mapping_info
    assert len(map_info) == 1
    assert map_info[0].address == 0x180000000
    assert map_info[0].size == 0x80000
    assert map_info[0].end_address == 0x180080000
    assert map_info[0].file_offset == 0
    assert map_info[0].max_prot == 5
    assert map_info[0].init_prot == 5

    assert dsc.has_subcaches
    subcaches = dsc.subcaches

    assert len(subcaches) == 62
    assert subcaches[0].suffix == ".01"
    assert subcaches[0].vm_offset == 0x80000
    assert subcaches[0].cache.filename == "dyld_shared_cache_arm64e.01"
    assert bytes(subcaches[0].uuid).hex(":") == "9e:52:2b:55:1d:d4:33:c3:b1:b1:2b:88:a8:a3:99:28"
    assert str(subcaches[0])
