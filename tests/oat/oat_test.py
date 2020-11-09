#!/usr/bin/env python
import json
import logging
import os
import pprint
import unittest
from unittest import TestCase

import lief
from utils import get_sample

lief.logging.set_level(lief.logging.LOGGING_LEVEL.INFO)

CURRENT_DIR = os.path.abspath(os.path.dirname(__file__))

class TestOAT64(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_multidex(self):
        WallpaperCropper2 = lief.parse(get_sample("OAT/OAT_064_AArch64_WallpaperCropper2.oat"))

        self.assertEqual(len(WallpaperCropper2.dex_files), 3)

    def test_header(self):
        WallpaperCropper2 = lief.parse(get_sample("OAT/OAT_064_AArch64_WallpaperCropper2.oat"))
        header = WallpaperCropper2.header

        self.assertEqual(header.magic, [111, 97, 116, 10])
        self.assertEqual(header.version, 64)
        self.assertEqual(header.checksum, 3369241059)
        self.assertEqual(header.instruction_set, lief.OAT.INSTRUCTION_SETS.ARM_64)
        self.assertEqual(header.nb_dex_files, 3)

        self.assertEqual(header.oat_dex_files_offset, 0)

        self.assertEqual(header.executable_offset, 3846144)
        self.assertEqual(header.i2i_bridge_offset, 0)
        self.assertEqual(header.i2c_code_bridge_offset, 0)
        self.assertEqual(header.jni_dlsym_lookup_offset, 0)
        self.assertEqual(header.quick_generic_jni_trampoline_offset, 0)
        self.assertEqual(header.quick_imt_conflict_trampoline_offset, 0)
        self.assertEqual(header.quick_resolution_trampoline_offset, 0)
        self.assertEqual(header.quick_to_interpreter_bridge_offset, 0)

        self.assertEqual(header.image_patch_delta, 0)

        self.assertEqual(header.image_file_location_oat_checksum, 285056181)
        self.assertEqual(header.image_file_location_oat_data_begin, 1897058304)

    def test_dex_files(self):
        WallpaperCropper2 = lief.parse(get_sample("OAT/OAT_064_AArch64_WallpaperCropper2.oat"))
        dex_files = WallpaperCropper2.dex_files

        self.assertEqual(len(dex_files), WallpaperCropper2.header.nb_dex_files)

        # Dex File 0
        dex = dex_files[0]
        self.assertEqual(dex.name, "classes.dex")
        self.assertEqual(dex.location, "/system/priv-app/WallpaperCropper2/WallpaperCropper2.apk")
        self.assertEqual(len(dex.raw(deoptimize=False)), dex.header.file_size)

        # Dex File 1
        dex = dex_files[1]
        #self.assertEqual(dex.name, "classes2.dex")
        self.assertEqual(dex.location, "/system/priv-app/WallpaperCropper2/WallpaperCropper2.apk:classes2.dex")
        self.assertEqual(len(dex.raw(deoptimize=False)), dex.header.file_size)

        # Dex File 2
        dex = dex_files[2]
        #self.assertEqual(dex.name, "classes3.dex")
        self.assertEqual(dex.location, "/system/priv-app/WallpaperCropper2/WallpaperCropper2.apk:classes3.dex")
        self.assertEqual(len(dex.raw(deoptimize=False)), dex.header.file_size)


    def test_oat_dex_files(self):
        WallpaperCropper2 = lief.parse(get_sample("OAT/OAT_064_AArch64_WallpaperCropper2.oat"))
        self.assertEqual(len(WallpaperCropper2.oat_dex_files), 3)

        # OAT Dex File 0
        oat_dex_file = WallpaperCropper2.oat_dex_files[0]

        self.assertEqual(oat_dex_file.location, "/system/priv-app/WallpaperCropper2/WallpaperCropper2.apk")
        self.assertEqual(oat_dex_file.checksum, 0xbb07e4e)
        self.assertEqual(oat_dex_file.dex_offset, 0x23a4)
        self.assertTrue(oat_dex_file.has_dex_file)

        # OAT Dex File 1
        oat_dex_file = WallpaperCropper2.oat_dex_files[1]

        self.assertEqual(oat_dex_file.location, "/system/priv-app/WallpaperCropper2/WallpaperCropper2.apk:classes2.dex")
        self.assertEqual(oat_dex_file.checksum, 1150225935)
        self.assertEqual(oat_dex_file.dex_offset, 340324)
        self.assertTrue(oat_dex_file.has_dex_file)

        # OAT Dex File 2
        oat_dex_file = WallpaperCropper2.oat_dex_files[2]

        self.assertEqual(oat_dex_file.location, "/system/priv-app/WallpaperCropper2/WallpaperCropper2.apk:classes3.dex")
        self.assertEqual(oat_dex_file.checksum, 459332982)
        self.assertEqual(oat_dex_file.dex_offset, 1617040)
        self.assertTrue(oat_dex_file.has_dex_file)

    def test_oat_classes(self):
        WallpaperCropper2 = lief.parse(get_sample("OAT/OAT_064_AArch64_WallpaperCropper2.oat"))
        self.assertEqual(len(WallpaperCropper2.classes), 1992)

        # OAT Class 0
        cls = WallpaperCropper2.get_class("android.support.v4.widget.ViewDragHelper")

        self.assertEqual(cls.fullname, "Landroid/support/v4/widget/ViewDragHelper;")
        self.assertEqual(cls.index, 1066)
        self.assertEqual(len(cls.methods), 49)
        self.assertEqual(cls.status, lief.OAT.OAT_CLASS_STATUS.VERIFIED)
        self.assertEqual(cls.type, lief.OAT.OAT_CLASS_TYPES.SOME_COMPILED)

        # OAT Class 1
        cls = WallpaperCropper2.get_class("com.android.keyguard.KeyguardTransportControlView$SavedState$1")

        self.assertEqual(cls.fullname, "Lcom/android/keyguard/KeyguardTransportControlView$SavedState$1;")
        self.assertEqual(cls.index, 207)
        self.assertEqual(len(cls.methods), 5)
        self.assertEqual(cls.status, lief.OAT.OAT_CLASS_STATUS.INITIALIZED)
        self.assertEqual(cls.type, lief.OAT.OAT_CLASS_TYPES.ALL_COMPILED)

        # OAT Class 2
        cls = WallpaperCropper2.get_class("android.support.v4.os.ParcelableCompatCreatorHoneycombMR2Stub")

        self.assertEqual(cls.fullname, "Landroid/support/v4/os/ParcelableCompatCreatorHoneycombMR2Stub;")
        self.assertEqual(cls.index, 566)
        self.assertEqual(len(cls.methods), 2)
        self.assertEqual(cls.status, lief.OAT.OAT_CLASS_STATUS.INITIALIZED)
        self.assertEqual(cls.type, lief.OAT.OAT_CLASS_TYPES.ALL_COMPILED)

        s = sum(len(cls.methods) for cls in WallpaperCropper2.classes)
        self.assertEqual(len(WallpaperCropper2.methods), s)

        # dex_sum = sum(len(dex.classes) for dex in WallpaperCropper2.dex_files)
        # self.assertEqual(len(WallpaperCropper2.classes), dex_sum)

    def test_oat_methods(self):
        WallpaperCropper2 = lief.parse(get_sample("OAT/OAT_064_AArch64_WallpaperCropper2.oat"))
        self.assertEqual(len(WallpaperCropper2.methods), 13830)

        self.assertTrue(all(m.is_compiled for m in WallpaperCropper2.methods))

        # OAT Method 0
        # ============
        method = WallpaperCropper2.methods[0]
        self.assertEqual(method.name, "<init>")
        self.assertEqual(method.oat_class, WallpaperCropper2.get_class("com/android/gallery3d/ds/DsWallpaperSetting"))


        # OAT Method 100
        # ==============
        method = WallpaperCropper2.methods[100]
        self.assertEqual(method.name, "deleteTag")
        self.assertEqual(method.oat_class, WallpaperCropper2.get_class("com/android/gallery3d/exif/ExifInterface"))


class TestOAT79(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_multidex(self):
        hangout = lief.parse(get_sample("OAT/OAT_079_AArch64_Hangouts.oat"))

        self.assertEqual(len(hangout.dex_files), 2)

    def test_header(self):
        pm = lief.parse(get_sample("OAT/OAT_079_AArch64_pm.oat"))
        header = pm.header

        self.assertEqual(header.magic, [111, 97, 116, 10])
        self.assertEqual(header.version, 79)
        self.assertEqual(header.checksum, 2466303069)
        self.assertEqual(header.instruction_set, lief.OAT.INSTRUCTION_SETS.ARM_64)
        self.assertEqual(header.nb_dex_files, 1)

        self.assertEqual(header.oat_dex_files_offset, 0)

        self.assertEqual(header.executable_offset, 73728)
        self.assertEqual(header.i2i_bridge_offset, 0)
        self.assertEqual(header.i2c_code_bridge_offset, 0)
        self.assertEqual(header.jni_dlsym_lookup_offset, 0)
        self.assertEqual(header.quick_generic_jni_trampoline_offset, 0)
        self.assertEqual(header.quick_imt_conflict_trampoline_offset, 0)
        self.assertEqual(header.quick_resolution_trampoline_offset, 0)
        self.assertEqual(header.quick_to_interpreter_bridge_offset, 0)

        self.assertEqual(header.image_patch_delta, 0)

        self.assertEqual(header.image_file_location_oat_checksum, 3334846204)
        self.assertEqual(header.image_file_location_oat_data_begin, 1893416960)

    def test_decompile(self):
        calldeviceid = lief.parse(get_sample('OAT/OAT_079_x86-64_CallDeviceId.oat'))

        self.assertEqual(len(calldeviceid.dex_files), 1)

        dex2dex_json_info_lhs = json.loads(calldeviceid.dex2dex_json_info)
        dex2dex_json_info_rhs = {'classes.dex': {'Lre/android/art/CallDeviceId;': {'3': {'0': 0}}}}
        self.assertEqual(dex2dex_json_info_lhs, dex2dex_json_info_rhs)

    def test_dex_files(self):
        CallDeviceId = lief.parse(get_sample("OAT/OAT_079_x86-64_CallDeviceId.oat"))
        dex_files = CallDeviceId.dex_files

        self.assertEqual(len(dex_files), CallDeviceId.header.nb_dex_files)

        # Dex File 0
        dex = dex_files[0]
        self.assertEqual(dex.name, "classes.dex")
        self.assertEqual(dex.location, "/data/local/tmp/CallDeviceId.dex")
        self.assertEqual(len(dex.raw(deoptimize=False)), dex.header.file_size)



    def test_oat_dex_files(self):
        CallDeviceId = lief.parse(get_sample("OAT/OAT_079_x86-64_CallDeviceId.oat"))
        self.assertEqual(len(CallDeviceId.oat_dex_files), 1)

        # OAT Dex File 0
        oat_dex_file = CallDeviceId.oat_dex_files[0]

        self.assertEqual(oat_dex_file.location, "/data/local/tmp/CallDeviceId.dex")
        self.assertEqual(oat_dex_file.checksum, 284645792)
        self.assertEqual(oat_dex_file.dex_offset, 1320)
        self.assertTrue(oat_dex_file.has_dex_file)

    def test_oat_classes(self):
        CallDeviceId = lief.parse(get_sample("OAT/OAT_079_x86-64_CallDeviceId.oat"))
        self.assertEqual(len(CallDeviceId.classes), 1)

        # OAT Class 0
        cls = CallDeviceId.classes[0]

        self.assertEqual(cls.fullname, "Lre/android/art/CallDeviceId;")
        self.assertEqual(cls.index, 0)
        self.assertEqual(len(cls.methods), 1)
        self.assertEqual(cls.status, lief.OAT.OAT_CLASS_STATUS.INITIALIZED)
        self.assertEqual(cls.type, lief.OAT.OAT_CLASS_TYPES.SOME_COMPILED)


    def test_oat_methods(self):
        CallDeviceId = lief.parse(get_sample("OAT/OAT_079_x86-64_CallDeviceId.oat"))
        self.assertEqual(len(CallDeviceId.methods), 1)

        self.assertTrue(all(m.is_dex2dex_optimized for m in CallDeviceId.methods))

        # OAT Method 0
        # ============
        method = CallDeviceId.methods[0]
        self.assertEqual(method.name, "getIMEI")
        self.assertEqual(method.oat_class, CallDeviceId.get_class("Lre/android/art/CallDeviceId;"))

class TestOAT124(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_header(self):
        emode = lief.parse(get_sample("OAT/OAT_124_AArch64_EngineeringMode.oat"))
        header = emode.header

        self.assertEqual(header.magic, [111, 97, 116, 10])
        self.assertEqual(header.version, 124)
        self.assertEqual(header.checksum, 2299270308)
        self.assertEqual(header.instruction_set, lief.OAT.INSTRUCTION_SETS.ARM_64)
        self.assertEqual(header.nb_dex_files, 1)

        self.assertEqual(header.oat_dex_files_offset, 0)

        self.assertEqual(header.executable_offset, 65536)
        self.assertEqual(header.i2i_bridge_offset, 0)
        self.assertEqual(header.i2c_code_bridge_offset, 0)
        self.assertEqual(header.jni_dlsym_lookup_offset, 0)
        self.assertEqual(header.quick_generic_jni_trampoline_offset, 0)
        self.assertEqual(header.quick_imt_conflict_trampoline_offset, 0)
        self.assertEqual(header.quick_resolution_trampoline_offset, 0)
        self.assertEqual(header.quick_to_interpreter_bridge_offset, 0)

        self.assertEqual(header.image_patch_delta, 0)

        self.assertEqual(header.image_file_location_oat_checksum, 1759409278)
        self.assertEqual(header.image_file_location_oat_data_begin, 1893093376)

    def test_oat_dex_files(self):
        CallDeviceId = lief.parse(get_sample("OAT/OAT_124_x86-64_CallDeviceId.oat"))
        self.assertEqual(len(CallDeviceId.oat_dex_files), 1)

        # OAT Dex File 0
        oat_dex_file = CallDeviceId.oat_dex_files[0]

        self.assertEqual(oat_dex_file.location, "/data/local/tmp/CallDeviceId.dex")
        self.assertEqual(oat_dex_file.checksum, 284645792)
        self.assertEqual(oat_dex_file.dex_offset, 28)
        self.assertFalse(oat_dex_file.has_dex_file)

    def test_oat_classes(self):
        oat_file  = get_sample("OAT/OAT_124_x86-64_CallDeviceId.oat")
        vdex_file = get_sample("VDEX/VDEX_06_x86-64_CallDeviceId.vdex")

        CallDeviceId = lief.OAT.parse(oat_file, vdex_file)
        self.assertEqual(len(CallDeviceId.classes), 1)

        # OAT Class 0
        cls = CallDeviceId.classes[0]

        self.assertEqual(cls.fullname, "Lre/android/art/CallDeviceId;")
        self.assertEqual(cls.index, 0)
        self.assertEqual(len(cls.methods), 1)
        self.assertEqual(cls.status, lief.OAT.OAT_CLASS_STATUS.INITIALIZED)
        self.assertEqual(cls.type, lief.OAT.OAT_CLASS_TYPES.SOME_COMPILED)


    def test_oat_methods(self):
        oat_file  = get_sample("OAT/OAT_124_x86-64_CallDeviceId.oat")
        vdex_file = get_sample("VDEX/VDEX_06_x86-64_CallDeviceId.vdex")

        CallDeviceId = lief.OAT.parse(oat_file, vdex_file)
        self.assertEqual(len(CallDeviceId.methods), 1)

        self.assertTrue(all(m.is_dex2dex_optimized for m in CallDeviceId.methods))

        # OAT Method 0
        # ============
        method = CallDeviceId.methods[0]
        self.assertEqual(method.name, "getIMEI")
        self.assertEqual(method.oat_class, CallDeviceId.get_class("Lre/android/art/CallDeviceId;"))


class TestOAT131(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_header(self):
        CallDeviceId = lief.parse(get_sample("OAT/OAT_131_x86_CallDeviceId.oat"))
        header = CallDeviceId.header

        self.assertEqual(header.magic, [111, 97, 116, 10])
        self.assertEqual(header.version, 131)
        self.assertEqual(header.checksum, 0x8e82f9b5)
        self.assertEqual(header.instruction_set, lief.OAT.INSTRUCTION_SETS.X86)
        self.assertEqual(header.nb_dex_files, 1)

        self.assertEqual(header.oat_dex_files_offset, 1484)

        self.assertEqual(header.executable_offset, 0x1000)
        self.assertEqual(header.i2i_bridge_offset, 0)
        self.assertEqual(header.i2c_code_bridge_offset, 0)
        self.assertEqual(header.jni_dlsym_lookup_offset, 0)
        self.assertEqual(header.quick_generic_jni_trampoline_offset, 0)
        self.assertEqual(header.quick_imt_conflict_trampoline_offset, 0)
        self.assertEqual(header.quick_resolution_trampoline_offset, 0)
        self.assertEqual(header.quick_to_interpreter_bridge_offset, 0)

        self.assertEqual(header.image_patch_delta, 15335424)

        self.assertEqual(header.image_file_location_oat_checksum, 0xdacfe293)
        self.assertEqual(header.image_file_location_oat_data_begin, 0x716a9000)

    def test_oat_dex_files(self):
        CallDeviceId = lief.parse(get_sample("OAT/OAT_131_x86_CallDeviceId.oat"))
        self.assertEqual(len(CallDeviceId.oat_dex_files), 1)

        # OAT Dex File 0
        oat_dex_file = CallDeviceId.oat_dex_files[0]

        self.assertEqual(oat_dex_file.location, "/data/local/tmp/CallDeviceId.dex")
        self.assertEqual(oat_dex_file.checksum, 284645792)
        self.assertEqual(oat_dex_file.dex_offset, 28)
        self.assertFalse(oat_dex_file.has_dex_file)

    def test_oat_classes(self):
        oat_file  = get_sample("OAT/OAT_131_x86_CallDeviceId.oat")
        vdex_file = get_sample("VDEX/VDEX_10_x86_CallDeviceId.vdex")

        #oat_file  = get_sample("OAT/OAT_131_AArch64_svc.oat")
        #vdex_file = get_sample("VDEX/VDEX_10_AArch64_svc.vdex")

        CallDeviceId = lief.OAT.parse(oat_file, vdex_file)
        self.assertEqual(len(CallDeviceId.classes), 1)

        # OAT Class 0
        cls = CallDeviceId.classes[0]

        self.assertEqual(cls.fullname, "Lre/android/art/CallDeviceId;")
        self.assertEqual(cls.index, 0)
        self.assertEqual(len(cls.methods), 0)
        #self.assertEqual(cls.status, lief.OAT.OAT_CLASS_STATUS.INITIALIZED) # TODO
        self.assertEqual(cls.type, lief.OAT.OAT_CLASS_TYPES.NONE_COMPILED)

    def test_oat_methods(self):
        oat_file  = get_sample("OAT/OAT_124_x86-64_CallDeviceId.oat")
        vdex_file = get_sample("VDEX/VDEX_06_x86-64_CallDeviceId.vdex")

        CallDeviceId = lief.OAT.parse(oat_file, vdex_file)
        self.assertEqual(len(CallDeviceId.methods), 1)

        self.assertTrue(all(m.is_dex2dex_optimized for m in CallDeviceId.methods))

        # OAT Method 0
        # ============
        method = CallDeviceId.methods[0]
        self.assertEqual(method.name, "getIMEI")
        self.assertEqual(method.oat_class, CallDeviceId.get_class("Lre/android/art/CallDeviceId;"))

class TestOAT138(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_header(self):
        CallDeviceId = lief.parse(get_sample("OAT/OAT_138_AArch64_android.uid.systemui.oat"))
        header = CallDeviceId.header

        self.assertEqual(header.magic, [111, 97, 116, 10])
        self.assertEqual(header.version, 138)
        self.assertEqual(header.checksum, 0x5c64d148)
        self.assertEqual(header.instruction_set, lief.OAT.INSTRUCTION_SETS.ARM_64)
        self.assertEqual(header.nb_dex_files, 1)

        self.assertEqual(header.oat_dex_files_offset, 3289146)

        self.assertEqual(header.executable_offset, 0x324000)
        self.assertEqual(header.i2i_bridge_offset, 0)
        self.assertEqual(header.i2c_code_bridge_offset, 0)
        self.assertEqual(header.jni_dlsym_lookup_offset, 0)
        self.assertEqual(header.quick_generic_jni_trampoline_offset, 0)
        self.assertEqual(header.quick_imt_conflict_trampoline_offset, 0)
        self.assertEqual(header.quick_resolution_trampoline_offset, 0)
        self.assertEqual(header.quick_to_interpreter_bridge_offset, 0)

        self.assertEqual(header.image_patch_delta, 0)

        self.assertEqual(header.image_file_location_oat_checksum, 0x8eb74f9a)
        self.assertEqual(header.image_file_location_oat_data_begin, 0x71242000)



class TestOAT(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_header_key_values(self):
        CallDeviceId = lief.parse(get_sample('OAT/OAT_079_x86-64_CallDeviceId.oat'))
        header = CallDeviceId.header

        self.assertEqual(header[lief.OAT.HEADER_KEYS.IMAGE_LOCATION],
                "/data/dalvik-cache/x86_64/system@framework@boot.art:"
                "/data/dalvik-cache/x86_64/system@framework@boot-core-libart.art:/data/dalvik-cache/x86_64/system@framework@boot-conscrypt.art:"
                "/data/dalvik-cache/x86_64/system@framework@boot-okhttp.art:/data/dalvik-cache/x86_64/system@framework@boot-core-junit.art:"
                "/data/dalvik-cache/x86_64/system@framework@boot-bouncycastle.art:/data/dalvik-cache/x86_64/system@framework@boot-ext.art:"
                "/data/dalvik-cache/x86_64/system@framework@boot-framework.art:/data/dalvik-cache/x86_64/system@framework@boot-telephony-common.art:"
                "/data/dalvik-cache/x86_64/system@framework@boot-voip-common.art:/data/dalvik-cache/x86_64/system@framework@boot-ims-common.art:"
                "/data/dalvik-cache/x86_64/system@framework@boot-apache-xml.art:/data/dalvik-cache/x86_64/system@framework@boot-org.apache.http.legacy.boot.art")

        self.assertEqual(header[lief.OAT.HEADER_KEYS.DEX2OAT_CMD_LINE],
                "--dex-file=/data/local/tmp/CallDeviceId.dex --oat-file=/data/local/tmp/CallDeviceId.oat "
                "--boot-image=/system/framework/boot.art --instruction-set=x86_64 "
                "--compiler-filter=interpret-only --compiler-backend=Quick")

        self.assertEqual(header[lief.OAT.HEADER_KEYS.PIC], "false")
        self.assertEqual(header[lief.OAT.HEADER_KEYS.HAS_PATCH_INFO], "false")
        self.assertEqual(header[lief.OAT.HEADER_KEYS.DEBUGGABLE], "false")
        self.assertEqual(header[lief.OAT.HEADER_KEYS.NATIVE_DEBUGGABLE], "false")
        self.assertEqual(header[lief.OAT.HEADER_KEYS.COMPILER_FILTER], "interpret-only")

        header[lief.OAT.HEADER_KEYS.DEBUGGABLE] = "true"
        self.assertEqual(header[lief.OAT.HEADER_KEYS.DEBUGGABLE], "true")

        self.assertEqual(len(header.keys), 8)

        for e in header.key_values:
            self.assertEqual(header[e.key], e.value)

        for x in header.key_values:
            x.value = "foo"

        self.assertTrue(all(k == "foo" for k in header.values))

if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)
