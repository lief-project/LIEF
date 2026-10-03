import lief
import pytest
from lief.runtime import MemoryLayout

if not lief.runtime.enabled:
    pytest.skip("skipping: needs runtime support", allow_module_level=True)

if lief.runtime.platform not in {
    lief.runtime.PLATFORMS.LINUX,
    lief.runtime.PLATFORMS.ANDROID,
    lief.runtime.PLATFORMS.OSX,
}:
    pytest.skip("skipping: unsupported memory layout", allow_module_level=True)


@pytest.mark.lief_extended
def test_basic():
    regions = list(lief.runtime.memory_layout())
    assert len(regions) > 0

    previous_end = 0
    for region in regions:
        assert isinstance(region, MemoryLayout.Region)
        assert isinstance(region.name, str)

        assert region.size > 0
        assert previous_end <= region.addr
        assert region.end_addr == region.addr + region.size
        assert region.contains(region.addr)
        assert not region.contains(region.end_addr)
        assert len(str(region)) > 0
        previous_end = region.end_addr
