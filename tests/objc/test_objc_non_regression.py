import lief
import pytest
from pathlib import Path
from utils import get_sample

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

def test_small_method():
    """
    Make sure the "relative" offset is correctly defined
    """

    macho = lief.MachO.parse(get_sample("MachO/ios17/DebugHierarchyKit")).at(0)
    metadata = macho.objc_metadata
    assert metadata is not None
    DBGDataCoordinator = metadata.get_class("DBGDataCoordinator")

    methods = list(DBGDataCoordinator.methods)

    assert methods[0].address == 0x15af8
