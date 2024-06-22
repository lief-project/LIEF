#!/usr/bin/env python
import lief
from utils import get_sample

lief.logging.set_level(lief.logging.LEVEL.INFO)

def test_header_key_values():
    CallDeviceId = lief.parse(get_sample('OAT/OAT_079_x86-64_CallDeviceId.oat'))
    header = CallDeviceId.header

    assert header[lief.OAT.HEADER_KEYS.IMAGE_LOCATION] == \
            "/data/dalvik-cache/x86_64/system@framework@boot.art:" \
            "/data/dalvik-cache/x86_64/system@framework@boot-core-libart.art:/data/dalvik-cache/x86_64/system@framework@boot-conscrypt.art:" \
            "/data/dalvik-cache/x86_64/system@framework@boot-okhttp.art:/data/dalvik-cache/x86_64/system@framework@boot-core-junit.art:" \
            "/data/dalvik-cache/x86_64/system@framework@boot-bouncycastle.art:/data/dalvik-cache/x86_64/system@framework@boot-ext.art:" \
            "/data/dalvik-cache/x86_64/system@framework@boot-framework.art:/data/dalvik-cache/x86_64/system@framework@boot-telephony-common.art:" \
            "/data/dalvik-cache/x86_64/system@framework@boot-voip-common.art:/data/dalvik-cache/x86_64/system@framework@boot-ims-common.art:" \
            "/data/dalvik-cache/x86_64/system@framework@boot-apache-xml.art:/data/dalvik-cache/x86_64/system@framework@boot-org.apache.http.legacy.boot.art"

    assert header[lief.OAT.HEADER_KEYS.DEX2OAT_CMD_LINE] == \
            "--dex-file=/data/local/tmp/CallDeviceId.dex --oat-file=/data/local/tmp/CallDeviceId.oat " \
            "--boot-image=/system/framework/boot.art --instruction-set=x86_64 " \
            "--compiler-filter=interpret-only --compiler-backend=Quick"

    assert header[lief.OAT.HEADER_KEYS.PIC] == "false"
    assert header[lief.OAT.HEADER_KEYS.HAS_PATCH_INFO] == "false"
    assert header[lief.OAT.HEADER_KEYS.DEBUGGABLE] == "false"
    assert header[lief.OAT.HEADER_KEYS.NATIVE_DEBUGGABLE] == "false"
    assert header[lief.OAT.HEADER_KEYS.COMPILER_FILTER] == "interpret-only"

    header[lief.OAT.HEADER_KEYS.DEBUGGABLE] = "true"
    assert header[lief.OAT.HEADER_KEYS.DEBUGGABLE] == "true"

    assert len(header.keys) == 8

    for e in header.key_values:
        assert header[e.key] == e.value

    for x in header.key_values:
        x.value = "foo"

    assert all(k == "foo" for k in header.values)

