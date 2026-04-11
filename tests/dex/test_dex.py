import lief
from utils import get_sample

_kik = lief.DEX.parse(get_sample("DEX/DEX35_kik.android.12.8.0.dex"))
assert _kik is not None
KIK = _kik


def test_header():
    header = KIK.header

    assert header.magic == [100, 101, 120, 10, 48, 51, 53, 0]
    assert header.checksum == 0x5EABACD
    assert header.signature == [
        222,
        148,
        89,
        234,
        112,
        212,
        217,
        127,
        146,
        201,
        101,
        115,
        66,
        163,
        44,
        125,
        125,
        142,
        208,
        242,
    ]
    assert header.file_size == 0x78AC64
    assert header.header_size == 0x70
    assert header.endian_tag == 0x12345678
    assert header.map_offset == 0x78AB88
    assert header.strings == (0x70, 51568)
    assert header.link == (0, 0)
    assert header.types == (0x32630, 12530)
    assert header.prototypes == (0x3E9F8, 14734)
    assert header.fields == (0x69CA0, 33376)
    assert header.methods == (0xAAFA0, 65254)
    assert header.classes == (0x12A6D0, 6893)
    assert header.data == (0x160470, 6465524)


def test_kik_class():
    classes = KIK.classes
    assert len(classes) == 12123

    c0 = KIK.get_class("android.graphics.drawable.ShapeDrawable")
    assert c0 is not None
    assert c0.pretty_name == "android.graphics.drawable.ShapeDrawable"
    assert len(c0.methods) == 3

    cls = KIK.get_class(
        "com.kik.video.mobile.KikVideoService$JoinConvoConferenceResponse$Result"
    )
    assert cls is not None
    assert cls.access_flags == [
        lief.DEX.ACCESS_FLAGS.PUBLIC,
        lief.DEX.ACCESS_FLAGS.FINAL,
        lief.DEX.ACCESS_FLAGS.ENUM,
    ]

    assert cls.source_filename == "SourceFile"
    assert cls.package_name == "com/kik/video/mobile"
    assert cls.name == "KikVideoService$JoinConvoConferenceResponse$Result"
    _parent = cls.parent
    assert _parent is not None
    assert _parent.pretty_name == "java.lang.Enum"
    assert len(cls.methods) == 14
    assert cls.index == 6220

    methods_name = sorted(list(set(m.name for m in cls.methods)))
    assert methods_name == sorted(
        [
            "<clinit>",
            "<init>",
            "forNumber",
            "getDescriptor",
            "internalGetValueMap",
            "valueOf",
            "values",
            "getDescriptorForType",
            "getNumber",
            "getValueDescriptor",
            "clone",
            "ordinal",
        ]
    )


def test_kik_methods():
    methods = KIK.methods

    assert len(methods) == 65254

    # external method: defined in the framework
    ValueAnimator = KIK.get_class("android.animation.ValueAnimator")
    assert ValueAnimator is not None
    m0 = ValueAnimator.get_method("setRepeatMode")[0]

    assert m0.name == "setRepeatMode"
    _m0_cls = m0.cls
    assert _m0_cls is not None
    assert _m0_cls.pretty_name == "android.animation.ValueAnimator"
    assert m0.code_offset == 0
    assert m0.bytecode == []
    assert m0.index == 100
    # assert m0.is_virtual == False # TODO
    _proto0 = m0.prototype
    assert _proto0 is not None
    _ret0 = _proto0.return_type
    assert _ret0 is not None
    assert _ret0.value == lief.DEX.Type.PRIMITIVES.VOID_T
    assert m0.access_flags == []
    assert (
        m0.code_info.nb_registers == 0
    )  # defined in the framework, only the prototype is defined in this dex file

    # internal method: defined in the current dex file
    SafetyNetValidator = KIK.get_class("kik.android.challenge.SafetyNetValidator")
    assert SafetyNetValidator is not None
    m1 = SafetyNetValidator.get_method("onConnected")[0]
    assert m1.name == "onConnected"
    _m1_cls = m1.cls
    assert _m1_cls is not None
    assert _m1_cls.pretty_name == "kik.android.challenge.SafetyNetValidator"
    assert m1.code_offset == 0x46DB88
    assert m1.bytecode == [
        0x55,
        0x10,
        0xC0,
        0x72,
        0x38,
        0x00,
        0x08,
        0x00,
        0x12,
        0x00,
        0x5C,
        0x10,
        0xC0,
        0x72,
        0x70,
        0x10,
        0x76,
        0xD0,
        0x01,
        0x00,
        0x0E,
        0x00,
    ]
    _proto1 = m1.prototype
    assert _proto1 is not None
    _ret1 = _proto1.return_type
    assert _ret1 is not None
    assert _ret1.value == lief.DEX.Type.PRIMITIVES.VOID_T
    assert m1.access_flags == [lief.DEX.ACCESS_FLAGS.PUBLIC]
    assert m1.code_info.nb_registers == 3


def test_kik_fields():
    fields = KIK.fields

    assert len(fields) == 33376

    Result = KIK.get_class(
        "com.kik.video.mobile.KikVideoService$JoinConvoConferenceResponse$Result"
    )
    assert Result is not None
    if0 = Result.get_field("value")[0]
    sf0 = Result.get_field("FULL")[0]

    assert if0.name == "value"
    _if0_cls = if0.cls
    assert _if0_cls is not None
    assert (
        _if0_cls.pretty_name
        == "com.kik.video.mobile.KikVideoService$JoinConvoConferenceResponse$Result"
    )
    _if0_type = if0.type
    assert _if0_type is not None
    assert _if0_type.value == lief.DEX.Type.PRIMITIVES.INT
    assert not if0.is_static
    assert if0.access_flags == [
        lief.DEX.ACCESS_FLAGS.PRIVATE,
        lief.DEX.ACCESS_FLAGS.FINAL,
    ]

    assert sf0.name == "FULL"
    _sf0_cls = sf0.cls
    assert _sf0_cls is not None
    assert (
        _sf0_cls.pretty_name
        == "com.kik.video.mobile.KikVideoService$JoinConvoConferenceResponse$Result"
    )
    _sf0_type = sf0.type
    assert _sf0_type is not None
    assert (
        _sf0_type.value.pretty_name  # type: ignore
        == "com.kik.video.mobile.KikVideoService$JoinConvoConferenceResponse$Result"
    )
    assert sf0.is_static
    assert sf0.access_flags == [
        lief.DEX.ACCESS_FLAGS.PUBLIC,
        lief.DEX.ACCESS_FLAGS.STATIC,
        lief.DEX.ACCESS_FLAGS.FINAL,
        lief.DEX.ACCESS_FLAGS.ENUM,
    ]


def test_kik_iterators():
    ValueAnimator = KIK.get_class("android.animation.ValueAnimator")
    assert ValueAnimator is not None
    assert len(list(ValueAnimator.get_method("test"))) == 0
    assert len(list(ValueAnimator.get_method("setValues"))) == 1
