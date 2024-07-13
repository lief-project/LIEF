'''
Some DroidGuard info from Objective-C metadata in iOS
'''
import lief
import pytest
from utils import get_sample, check_objc_dump
from pathlib import Path

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

def test_droidguard():
    macho = lief.MachO.parse(get_sample("private/MachO/Module_Framework")).at(0)
    metadata = macho.objc_metadata
    assert metadata is not None

    classes = list(metadata.classes)
    assert len(classes) == 21866

    protocols = list(metadata.protocols)
    assert len(protocols) == 3168

    YTILogAttestationRequest = metadata.get_class("YTILogAttestationRequest")
    assert YTILogAttestationRequest is not None
    methods = list(YTILogAttestationRequest.methods)
    assert len(methods) == 1
    assert methods[0].name == "descriptor"
    assert methods[0].mangled_type == "@16@0:8"
    assert methods[0].address == 0x1f125c8
    assert not methods[0].is_instance

    protocols = list(YTILogAttestationRequest.protocols)
    assert len(protocols) == 0

    properties = list(YTILogAttestationRequest.properties)
    assert len(properties) == 15
    assert properties[6].name == "droidguardResponse"
    assert properties[6].attribute == 'T@"NSString",C,D,N'

    ivars = list(YTILogAttestationRequest.ivars)
    assert len(ivars) == 0

    GADGestureRecognizer = metadata.get_class("GADGestureRecognizer")
    ivars = list(GADGestureRecognizer.ivars)

    assert ivars[0].name == "_gestureInfo"
    assert ivars[0].mangled_type == "[29i]"

    PINCaching = metadata.get_protocol("PINCaching")
    assert PINCaching is not None

    assert PINCaching.mangled_name == "PINCaching"
    opt_methods = list(PINCaching.optional_methods)
    assert len(opt_methods) == 0

    req_methods = list(PINCaching.required_methods)
    assert len(req_methods) == 21

    assert req_methods[0].name == "containsObjectForKeyAsync:completion:"
    assert req_methods[0].address == 0

    properties = list(PINCaching.properties)
    assert len(properties) == 1
    assert properties[0].name == "name"
    assert properties[0].attribute == 'T@"NSString",R'

    check_objc_dump(metadata, Path(get_sample("private/MachO/Module_Framework.objdump")))
