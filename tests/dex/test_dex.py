#!/usr/bin/env python
import lief
from utils import get_sample

KIK       = lief.DEX.parse(get_sample('DEX/DEX35_kik.android.12.8.0.dex'))

def test_header():
    header = KIK.header

    assert header.magic       == [100, 101, 120, 10, 48, 51, 53, 0]
    assert header.checksum    == 0x5eabacd
    assert header.signature   == [222, 148, 89, 234, 112, 212, 217, 127, 146, 201, 101, 115, 66, 163, 44, 125, 125, 142, 208, 242]
    assert header.file_size   == 0x78ac64
    assert header.header_size == 0x70
    assert header.endian_tag  == 0x12345678
    assert header.map_offset  == 0x78ab88
    assert header.strings     == (0x70, 51568)
    assert header.link        == (0, 0)
    assert header.types       == (0x32630, 12530)
    assert header.prototypes  == (0x3e9f8, 14734)
    assert header.fields      == (0x69ca0, 33376)
    assert header.methods     == (0xaafa0, 65254)
    assert header.classes     == (0x12a6d0, 6893)
    assert header.data        == (0x160470, 6465524)

def test_kik_class():
    classes = KIK.classes
    assert len(classes) == 12123

    c0 = KIK.get_class("android.graphics.drawable.ShapeDrawable")
    assert c0.pretty_name == "android.graphics.drawable.ShapeDrawable"
    assert len(c0.methods) == 3

    cls = KIK.get_class("com.kik.video.mobile.KikVideoService$JoinConvoConferenceResponse$Result")
    assert cls.access_flags == [lief.DEX.ACCESS_FLAGS.PUBLIC,
                                lief.DEX.ACCESS_FLAGS.FINAL,
                                lief.DEX.ACCESS_FLAGS.ENUM]

    assert cls.source_filename    == "SourceFile"
    assert cls.package_name       == "com/kik/video/mobile"
    assert cls.name               == "KikVideoService$JoinConvoConferenceResponse$Result"
    assert cls.parent.pretty_name == "java.lang.Enum"
    assert len(cls.methods)       == 14
    assert cls.index              == 6220

    methods_name = sorted(list(set(m.name for m in cls.methods)))
    assert methods_name == sorted([
        '<clinit>', '<init>', 'forNumber', 'getDescriptor',
        'internalGetValueMap', 'valueOf', 'values', 'getDescriptorForType',
        'getNumber', 'getValueDescriptor',
        'clone', 'ordinal'])

def test_kik_methods():
    methods = KIK.methods

    assert len(methods) == 65254

    ValueAnimator = KIK.get_class("android.animation.ValueAnimator")
    m0 = ValueAnimator.get_method("setRepeatMode")[0]

    assert m0.name == "setRepeatMode"
    assert m0.cls.pretty_name == "android.animation.ValueAnimator"
    assert m0.code_offset == 0
    assert m0.bytecode == []
    assert m0.index == 100
    #assert m0.is_virtual == False # TODO
    assert m0.prototype.return_type.value == lief.DEX.Type.PRIMITIVES.VOID_T
    assert m0.access_flags == []


def test_kik_fields():
    fields = KIK.fields

    assert len(fields) == 33376

    Result = KIK.get_class("com.kik.video.mobile.KikVideoService$JoinConvoConferenceResponse$Result")
    if0 = Result.get_field("value")[0]
    sf0 = Result.get_field("FULL")[0]

    assert if0.name == "value"
    assert if0.cls.pretty_name == "com.kik.video.mobile.KikVideoService$JoinConvoConferenceResponse$Result"
    assert if0.type.value == lief.DEX.Type.PRIMITIVES.INT
    assert if0.is_static == False
    assert if0.access_flags == [lief.DEX.ACCESS_FLAGS.PRIVATE, lief.DEX.ACCESS_FLAGS.FINAL]

    assert sf0.name == "FULL"
    assert sf0.cls.pretty_name == "com.kik.video.mobile.KikVideoService$JoinConvoConferenceResponse$Result"
    assert sf0.type.value.pretty_name == "com.kik.video.mobile.KikVideoService$JoinConvoConferenceResponse$Result"
    assert sf0.is_static == True
    assert sf0.access_flags == [lief.DEX.ACCESS_FLAGS.PUBLIC, lief.DEX.ACCESS_FLAGS.STATIC,
                                lief.DEX.ACCESS_FLAGS.FINAL, lief.DEX.ACCESS_FLAGS.ENUM]

def test_kik_iterators():
    ValueAnimator = KIK.get_class("android.animation.ValueAnimator")
    assert len(list(ValueAnimator.get_method("test"))) == 0
    assert len(list(ValueAnimator.get_method("setValues"))) == 1






