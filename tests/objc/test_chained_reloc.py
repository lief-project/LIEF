# These tests test samples with the "new" chained relocations
# as described in this issue: https://github.com/romainthomas/iCDump/issues/4
from pathlib import Path

import lief
import pytest
from utils import check_objc_dump, get_sample, parse_macho

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)


def test_reloc_objc_classlist():
    """
    In this sample, the `__objc_classlist` table is filled with 0 and "patched"
    with the effective values with relocations
    """

    macho = parse_macho("MachO/ios17/DebugHierarchyKit").at(0)
    assert macho is not None
    metadata = macho.objc_metadata
    assert metadata is not None

    classes = list(metadata.classes)
    assert len(classes) == 48

    check_objc_dump(
        metadata, Path(get_sample("MachO/ios17/DebugHierarchyKit.objcdump"))
    )
