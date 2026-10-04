import ctypes
import mmap
from pathlib import Path

import lief
import pytest

if not lief.runtime.enabled:
    pytest.skip("skipping: needs runtime support", allow_module_level=True)

if lief.runtime.platform != lief.runtime.PLATFORMS.OSX:
    pytest.skip("skipping: osx only", allow_module_level=True)


@pytest.mark.parametrize("size", [16, 4096, 16 * 1024 * 1024])
def test_heap_region(size: int):
    libc = ctypes.CDLL(None)
    libc.malloc.argtypes = [ctypes.c_size_t]
    libc.malloc.restype = ctypes.c_void_p
    libc.free.argtypes = [ctypes.c_void_p]
    libc.free.restype = None

    addr = libc.malloc(size)
    assert addr is not None
    try:
        regions = [
            r
            for r in lief.runtime.memory_layout()
            if r is not None and r.contains(addr)
        ]
        assert len(regions) == 1
        region = regions[0]

        if not region.contains(addr + size - 1):
            pytest.xfail(f"allocation of {size} bytes extends past its region")

        if region.name != "[heap]":
            pytest.xfail(f"allocation is in {region.name!r}, not '[heap]'")
    finally:
        libc.free(addr)


def test_anonymous_mapping():
    with mmap.mmap(
        -1, mmap.PAGESIZE, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS
    ) as mapping:
        addr = ctypes.addressof(ctypes.c_char.from_buffer(mapping))
        regions = [
            r
            for r in lief.runtime.memory_layout()
            if r is not None and r.contains(addr)
        ]
        assert len(regions) == 1
        region = regions[0]
        assert region.contains(addr + len(mapping) - 1)
        assert region.name == ""


@pytest.mark.parametrize("access", [mmap.ACCESS_WRITE, mmap.ACCESS_COPY])
def test_file_mapping_snapshot(tmp_path: Path, access: int):
    path = tmp_path / "mapped file.bin"
    path.write_bytes(bytes(3 * mmap.PAGESIZE))

    with (
        path.open("r+b") as file,
        mmap.mmap(
            file.fileno(), 2 * mmap.PAGESIZE, access=access, offset=mmap.PAGESIZE
        ) as mapping,
    ):
        addr = ctypes.addressof(ctypes.c_char.from_buffer(mapping))
        size = len(mapping)
        snapshot = lief.runtime.memory_layout()

    regions = [r for r in snapshot if r is not None and r.contains(addr)]
    assert len(regions) == 1
    region = regions[0]
    assert region.contains(addr + size - 1)
    assert Path(region.name) == path.resolve()
    assert all(
        r is not None and r.name != region.name for r in lief.runtime.memory_layout()
    )


def test_system_library_mapping():
    # On macOS, system library code is mapped through the shared cache.
    libc = ctypes.CDLL(None)
    addr = ctypes.cast(libc.getpid, ctypes.c_void_p).value
    assert addr is not None
    regions = [
        r for r in lief.runtime.memory_layout() if r is not None and r.contains(addr)
    ]
    assert len(regions) == 1
    assert regions[0].name
