import ctypes

import lief
import pytest
from lief.runtime import Memory, MemoryLayout

if not lief.runtime.enabled:
    pytest.skip("skipping: needs runtime support", allow_module_level=True)

if lief.runtime.platform not in {
    lief.runtime.PLATFORMS.LINUX,
    lief.runtime.PLATFORMS.ANDROID,
    lief.runtime.PLATFORMS.OSX,
    lief.runtime.PLATFORMS.WINDOWS,
}:
    pytest.skip("skipping: unsupported memory layout", allow_module_level=True)


def find_region(regions: list[MemoryLayout.Region], addr: int) -> MemoryLayout.Region:
    matches = [r for r in regions if r.contains(addr)]
    assert len(matches) == 1
    return matches[0]


def snapshot() -> list[MemoryLayout.Region]:
    return [r for r in lief.runtime.memory_layout() if r is not None]


@pytest.mark.lief_extended
def test_basic():
    regions = list(lief.runtime.memory_layout())
    assert len(regions) > 0

    previous_end = 0
    for region in regions:
        assert isinstance(region, MemoryLayout.Region)
        assert isinstance(region.name, str)
        assert isinstance(region.permissions, Memory.PERM)

        assert region.size > 0
        assert previous_end <= region.addr
        assert region.end_addr == region.addr + region.size
        assert region.contains(region.addr)
        assert not region.contains(region.end_addr)
        assert Memory.perm_str(region.permissions) in str(region)
        previous_end = region.end_addr


@pytest.mark.lief_extended
def test_code_and_data_permissions():
    code = ctypes.cast(ctypes.pythonapi.Py_GetVersion, ctypes.c_void_p).value
    assert code is not None

    buffer = ctypes.create_string_buffer(0x100)
    rw = Memory.PERM.READ | Memory.PERM.WRITE

    regions = snapshot()
    assert find_region(regions, code).permissions & Memory.PERM.EXEC
    assert find_region(regions, ctypes.addressof(buffer)).permissions & rw == rw


@pytest.mark.lief_extended
def test_mprotect():
    page_size = lief.runtime.Process.page_size
    chunk = Memory.mmap(
        page_size, Memory.ANONYMOUS | Memory.PRIVATE, Memory.READ | Memory.WRITE
    )
    assert chunk is not None

    try:
        for perms in (
            Memory.PERM.READ | Memory.PERM.WRITE,
            Memory.PERM.READ,
            Memory.PERM.NONE,
        ):
            assert Memory.mprotect(chunk, perms)
            region = find_region(snapshot(), chunk.addr)
            assert region.contains(chunk.addr + page_size - 1)
            assert region.permissions == perms
            assert Memory.perm_str(perms) in str(region)
    finally:
        assert Memory.munmap(chunk)
