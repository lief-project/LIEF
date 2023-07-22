#!/usr/bin/env python

from lief import Android
from lief.Android import ANDROID_VERSIONS

def test_android_version():
    assert Android.code_name(ANDROID_VERSIONS.UNKNOWN)     == "UNKNOWN"
    assert Android.code_name(ANDROID_VERSIONS.VERSION_601) == "Marshmallow"
    assert Android.code_name(ANDROID_VERSIONS.VERSION_700) == "Nougat"
    assert Android.code_name(ANDROID_VERSIONS.VERSION_710) == "Nougat"
    assert Android.code_name(ANDROID_VERSIONS.VERSION_712) == "Nougat"
    assert Android.code_name(ANDROID_VERSIONS.VERSION_800) == "Oreo"
    assert Android.code_name(ANDROID_VERSIONS.VERSION_810) == "Oreo"
    assert Android.code_name(ANDROID_VERSIONS.VERSION_900) == "Pie"

    assert Android.version_string(ANDROID_VERSIONS.UNKNOWN)     == "UNKNOWN"
    assert Android.version_string(ANDROID_VERSIONS.VERSION_601) == "6.0.1"
    assert Android.version_string(ANDROID_VERSIONS.VERSION_700) == "7.0.0"
    assert Android.version_string(ANDROID_VERSIONS.VERSION_710) == "7.1.0"
    assert Android.version_string(ANDROID_VERSIONS.VERSION_712) == "7.1.2"
    assert Android.version_string(ANDROID_VERSIONS.VERSION_800) == "8.0.0"
    assert Android.version_string(ANDROID_VERSIONS.VERSION_810) == "8.1.0"
    assert Android.version_string(ANDROID_VERSIONS.VERSION_900) == "9.0.0"
