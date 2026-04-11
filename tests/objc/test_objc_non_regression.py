import lief
import pytest
from utils import parse_macho

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)


def test_small_method():
    """
    Make sure the "relative" offset is correctly defined
    """

    macho = parse_macho("MachO/ios17/DebugHierarchyKit").at(0)
    assert macho is not None
    metadata = macho.objc_metadata
    assert metadata is not None
    DBGDataCoordinator = metadata.get_class("DBGDataCoordinator")
    assert DBGDataCoordinator is not None

    methods = list(DBGDataCoordinator.methods)

    _m0 = methods[0]
    assert _m0 is not None
    assert _m0.address == 0x15AF8
