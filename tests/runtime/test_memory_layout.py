import lief
import pytest
from lief.runtime import MemoryLayout

if not lief.runtime.enabled:
    pytest.skip("skipping: needs runtime support", allow_module_level=True)


@pytest.mark.lief_extended
def test_basic():
    if lief.runtime.platform != lief.runtime.PLATFORMS.LINUX:
        pytest.skip("skipping: Linux only for now")
    regions = list(lief.runtime.memory_layout())
    assert len(regions) > 0

    for region in regions:
        assert isinstance(region, MemoryLayout.Region)
        assert isinstance(region.name, str)
        assert region.end_addr == region.addr + region.size
        assert region.contains(region.addr)
        assert not region.contains(region.end_addr)
        assert len(str(region)) > 0
