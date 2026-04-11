"""
Some DroidGuard info from Objective-C metadata in iOS
"""

from pathlib import Path
from textwrap import dedent

import lief
import pytest
from utils import check_objc_dump, get_sample, parse_macho

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)


def test_droidguard():
    macho = parse_macho("private/MachO/Module_Framework").at(0)
    assert macho is not None
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
    _m0 = methods[0]
    assert _m0 is not None
    assert _m0.name == "descriptor"
    assert _m0.mangled_type == "@16@0:8"
    assert _m0.address == 0x1F125C8
    assert not _m0.is_instance

    protocols = list(YTILogAttestationRequest.protocols)
    assert len(protocols) == 0

    properties = list(YTILogAttestationRequest.properties)
    assert len(properties) == 15
    _p6 = properties[6]
    assert _p6 is not None
    assert _p6.name == "droidguardResponse"
    assert _p6.attribute == 'T@"NSString",C,D,N'

    ivars = list(YTILogAttestationRequest.ivars)
    assert len(ivars) == 0

    GADGestureRecognizer = metadata.get_class("GADGestureRecognizer")
    assert GADGestureRecognizer is not None
    ivars = list(GADGestureRecognizer.ivars)

    _iv0 = ivars[0]
    assert _iv0 is not None
    assert _iv0.name == "_gestureInfo"
    assert _iv0.mangled_type == "[29i]"

    PINCaching = metadata.get_protocol("PINCaching")
    assert PINCaching is not None

    assert PINCaching.mangled_name == "PINCaching"
    opt_methods = list(PINCaching.optional_methods)
    assert len(opt_methods) == 0

    req_methods = list(PINCaching.required_methods)
    assert len(req_methods) == 21

    _rm0 = req_methods[0]
    assert _rm0 is not None
    assert _rm0.name == "containsObjectForKeyAsync:completion:"
    assert _rm0.address == 0

    properties = list(PINCaching.properties)
    assert len(properties) == 1
    _prop0 = properties[0]
    assert _prop0 is not None
    assert _prop0.name == "name"
    assert _prop0.attribute == 'T@"NSString",R'

    check_objc_dump(
        metadata, Path(get_sample("private/MachO/Module_Framework.objdump"))
    )
    assert YTILogAttestationRequest.to_decl() == dedent("""\
        @interface YTILogAttestationRequest
        // Address: 0x0001f125c8
        + (NSObject *)descriptor:(YTILogAttestationRequest *)self :(SEL)id;
        @property void context;
        @property void hasContext;
        @property void challenge;
        @property void hasChallenge;
        @property void xguardClientResponseOneOfCase;
        @property void botguardResponse;
        @property void droidguardResponse;
        @property void iosguardResponse;
        @property void webResponse;
        @property void androidResponse;
        @property void iosResponse;
        @property void engagementType;
        @property void hasEngagementType;
        @property void idsArray;
        @property void idsArray_Count;
        @end
        """)
