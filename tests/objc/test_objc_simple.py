import lief
import pytest
from utils import get_sample, check_objc_dump
from pathlib import Path

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

def test_crypto():
    crypto = lief.MachO.parse(get_sample("MachO/RNCryptor.bin")).at(0)
    metadata = crypto.objc_metadata

    classes = list(metadata.classes)
    assert len(classes) == 10

    assert classes[1].name == "_TtCO9RNCryptor9RNCryptor9Encryptor"
    assert classes[1].demangled_name == "RNCryptor.RNCryptor.Encryptor"
    assert classes[1].super_class is None
    assert not classes[0].is_meta

    methods = list(classes[0].methods)
    assert len(methods) == 0

    check_objc_dump(metadata, Path(get_sample("MachO/RNCryptor.objcdump")))

def test_ios_app():
    SP = lief.MachO.parse(get_sample("private/MachO/SingPass")).at(0)
    assert SP is not None
    metadata = SP.objc_metadata
    assert metadata is not None

    classes = list(metadata.classes)
    assert len(classes) == 571
    assert classes[0].name == "C8SingPass6sePhoe"
    assert classes[0].demangled_name == "C8SingPass6sePhoe"
    assert classes[0].super_class is None
    assert not classes[0].is_meta

    methods = list(classes[0].methods)
    assert len(methods) == 0

    protocols = list(classes[0].protocols)
    assert len(protocols) == 0

    properties = list(classes[0].properties)
    assert len(properties) == 0

    ivars = list(classes[0].ivars)
    assert len(ivars) == 12

    assert ivars[0].name == "Jvi0"
    assert ivars[0].mangled_type == ""

    assert ivars[11].name == "eBAl_q"
    assert ivars[11].mangled_type == ""

    check_objc_dump(metadata, Path(get_sample("private/MachO/SingPass.objcdump")))
