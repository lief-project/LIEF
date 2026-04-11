from pathlib import Path

import lief
import pytest
from utils import check_objc_dump, get_sample, parse_macho

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)


def test_crypto():
    crypto = parse_macho("MachO/RNCryptor.bin").at(0)
    assert crypto is not None
    metadata = crypto.objc_metadata
    assert metadata is not None

    classes = list(metadata.classes)
    assert len(classes) == 10

    _cls1 = classes[1]
    assert _cls1 is not None
    assert _cls1.name == "_TtCO9RNCryptor9RNCryptor9Encryptor"
    assert _cls1.demangled_name == "RNCryptor.RNCryptor.Encryptor"
    assert _cls1.super_class is None
    _cls0 = classes[0]
    assert _cls0 is not None
    assert not _cls0.is_meta

    methods = list(_cls0.methods)
    assert len(methods) == 0

    check_objc_dump(metadata, Path(get_sample("MachO/RNCryptor.objcdump")))


def test_ios_app():
    SP = parse_macho("private/MachO/SingPass").at(0)
    assert SP is not None
    metadata = SP.objc_metadata
    assert metadata is not None

    classes = list(metadata.classes)
    assert len(classes) == 571
    _cls0 = classes[0]
    assert _cls0 is not None
    assert _cls0.name == "C8SingPass6sePhoe"
    assert _cls0.demangled_name == "C8SingPass6sePhoe"
    assert _cls0.super_class is None
    assert not _cls0.is_meta

    methods = list(_cls0.methods)
    assert len(methods) == 0

    protocols = list(_cls0.protocols)
    assert len(protocols) == 0

    properties = list(_cls0.properties)
    assert len(properties) == 0

    ivars = list(_cls0.ivars)
    assert len(ivars) == 12

    _iv0 = ivars[0]
    assert _iv0 is not None
    assert _iv0.name == "Jvi0"
    assert _iv0.mangled_type == ""

    _iv11 = ivars[11]
    assert _iv11 is not None
    assert _iv11.name == "eBAl_q"
    assert _iv11.mangled_type == ""

    check_objc_dump(metadata, Path(get_sample("private/MachO/SingPass.objcdump")))
