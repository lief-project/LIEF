import lief
import pytest
from utils import get_sample


def test_one_liner():
    _parsed = lief.parse(get_sample("MachO/issue_853_classes_15.bin"))
    assert isinstance(_parsed, lief.MachO.Binary)
    assert len(_parsed.sections[0].name) > 0


def test_abstract_concrete():
    filepath = get_sample("PE/PE32_x86_binary_cmd.exe")
    _b1 = lief.parse(filepath)
    assert isinstance(_b1, lief.PE.Binary)
    assert isinstance(_b1.abstract, lief.Binary)
    _b2 = lief.parse(filepath)
    assert isinstance(_b2, lief.PE.Binary)
    assert isinstance(_b2.abstract.concrete, lief.PE.Binary)
    _b3 = lief.parse(filepath)
    assert isinstance(_b3, lief.PE.Binary)
    assert isinstance(_b3.concrete.abstract, lief.Binary)  # type: ignore
    _b4 = lief.parse(filepath)
    assert isinstance(_b4, lief.PE.Binary)
    assert isinstance(_b4.concrete.abstract.concrete, lief.PE.Binary)  # type: ignore


def test_invalid_enum():
    """From: issues/1128"""
    with pytest.raises(ValueError):
        lief.ELF.Header.VERSION.from_value(2)

    assert lief.ELF.Header.VERSION.from_value(0) == lief.ELF.Header.VERSION.NONE
