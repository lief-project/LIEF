import lief
import pytest
from lief.runtime import Memory

if not lief.runtime.enabled:
    pytest.skip("skipping: needs runtime support", allow_module_level=True)


@pytest.mark.runtime
def test_basic():
    chunk = Memory.mmap(
        0x4000, Memory.ANONYMOUS | Memory.PRIVATE, Memory.READ | Memory.WRITE
    )
    assert chunk is not None

    assert chunk.addr == lief.to_int(chunk.addr_ptr)
    assert chunk.size == 0x4000
    assert chunk.permissions == Memory.READ | Memory.WRITE
    assert Memory.perm_str(chunk.permissions) == "rw-"

    assert chunk.page_start < chunk.page_end
    chunk.cache_flush()
    assert str(chunk) != ""

    Memory.write_u32(0xDEADC0DE, chunk.addr)
    assert Memory.read_u32(chunk.addr) == 0xDEADC0DE

    chunk.make_x()
    chunk.make_rw()
    chunk.make_rx()
    chunk.make_rwx()
    chunk.make_ro()

    assert Memory.munmap(chunk)


@pytest.mark.runtime
def test_mmap_hint():
    page_size = lief.runtime.Process.page_size

    reserved = Memory.mmap(
        2 * page_size, Memory.ANONYMOUS | Memory.PRIVATE, Memory.READ | Memory.WRITE
    )
    assert reserved is not None

    # A misaligned hint is rounded up to the next page boundary
    chunk = Memory.mmap_hint(
        reserved.addr + page_size + 1,
        page_size,
        Memory.ANONYMOUS | Memory.PRIVATE,
        Memory.READ,
    )
    assert chunk is not None
    assert chunk.addr % page_size == 0
    assert chunk.size == page_size
    assert Memory.munmap(chunk)

    # A hint set to 0 is equivalent to Memory.mmap
    chunk = Memory.mmap_hint(
        0, page_size, Memory.ANONYMOUS | Memory.PRIVATE, Memory.READ
    )
    assert chunk is not None
    assert Memory.munmap(chunk)

    # A hint that can't be page-aligned is rejected
    assert (
        Memory.mmap_hint(
            0xFFFFFFFFFFFFFFFF,
            page_size,
            Memory.ANONYMOUS | Memory.PRIVATE,
            Memory.READ,
        )
        is None
    )

    assert Memory.munmap(reserved)


@pytest.mark.runtime
@pytest.mark.skipif(
    lief.runtime.platform == lief.runtime.PLATFORMS.WINDOWS,
    reason="VirtualAlloc can't remap an existing reservation",
)
def test_mmap_fixed():
    page_size = lief.runtime.Process.page_size

    # Own two pages so that the fixed mapping only discards our own memory
    reserved = Memory.mmap(
        2 * page_size, Memory.ANONYMOUS | Memory.PRIVATE, Memory.READ | Memory.WRITE
    )
    assert reserved is not None

    target = reserved.addr + page_size
    chunk = Memory.mmap_hint(
        target,
        page_size,
        Memory.ANONYMOUS | Memory.PRIVATE | Memory.FIXED,
        Memory.READ | Memory.WRITE,
    )
    assert chunk is not None
    assert chunk.addr == target

    Memory.write_u32(0xDEADC0DE, chunk.addr)
    assert Memory.read_u32(chunk.addr) == 0xDEADC0DE

    assert Memory.munmap(chunk)
    assert Memory.munmap(reserved)
