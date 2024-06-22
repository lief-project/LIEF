import lief
from utils import get_sample

lief.logging.set_level(lief.logging.LEVEL.INFO)

def test_multidex():
    WallpaperCropper2 = lief.parse(get_sample("OAT/OAT_064_AArch64_WallpaperCropper2.oat"))

    assert len(WallpaperCropper2.dex_files) == 3

def test_header():
    WallpaperCropper2 = lief.parse(get_sample("OAT/OAT_064_AArch64_WallpaperCropper2.oat"))
    header = WallpaperCropper2.header

    assert header.magic == [111, 97, 116, 10]
    assert header.version == 64
    assert header.checksum == 3369241059
    assert header.instruction_set == lief.OAT.INSTRUCTION_SETS.ARM_64
    assert header.nb_dex_files == 3

    assert header.oat_dex_files_offset == 0

    assert header.executable_offset == 3846144
    assert header.i2i_bridge_offset == 0
    assert header.i2c_code_bridge_offset == 0
    assert header.jni_dlsym_lookup_offset == 0
    assert header.quick_generic_jni_trampoline_offset == 0
    assert header.quick_imt_conflict_trampoline_offset == 0
    assert header.quick_resolution_trampoline_offset == 0
    assert header.quick_to_interpreter_bridge_offset == 0

    assert header.image_patch_delta == 0

    assert header.image_file_location_oat_checksum == 285056181
    assert header.image_file_location_oat_data_begin == 1897058304

def test_dex_files():
    WallpaperCropper2 = lief.parse(get_sample("OAT/OAT_064_AArch64_WallpaperCropper2.oat"))
    dex_files = WallpaperCropper2.dex_files

    assert len(dex_files) == WallpaperCropper2.header.nb_dex_files

    # Dex File 0
    dex = dex_files[0]
    assert dex.name == "classes.dex"
    assert dex.location == "/system/priv-app/WallpaperCropper2/WallpaperCropper2.apk"
    assert len(dex.raw(deoptimize=False)) == dex.header.file_size

    # Dex File 1
    dex = dex_files[1]
    #assert dex.name == "classes2.dex"
    assert dex.location == "/system/priv-app/WallpaperCropper2/WallpaperCropper2.apk:classes2.dex"
    assert len(dex.raw(deoptimize=False)) == dex.header.file_size

    # Dex File 2
    dex = dex_files[2]
    #assert dex.name == "classes3.dex"
    assert dex.location == "/system/priv-app/WallpaperCropper2/WallpaperCropper2.apk:classes3.dex"
    assert len(dex.raw(deoptimize=False)) == dex.header.file_size


def test_oat_dex_files():
    WallpaperCropper2 = lief.parse(get_sample("OAT/OAT_064_AArch64_WallpaperCropper2.oat"))
    assert len(WallpaperCropper2.oat_dex_files) == 3

    # OAT Dex File 0
    oat_dex_file = WallpaperCropper2.oat_dex_files[0]

    assert oat_dex_file.location == "/system/priv-app/WallpaperCropper2/WallpaperCropper2.apk"
    assert oat_dex_file.checksum == 0xbb07e4e
    assert oat_dex_file.dex_offset == 0x23a4
    assert oat_dex_file.has_dex_file

    # OAT Dex File 1
    oat_dex_file = WallpaperCropper2.oat_dex_files[1]

    assert oat_dex_file.location == "/system/priv-app/WallpaperCropper2/WallpaperCropper2.apk:classes2.dex"
    assert oat_dex_file.checksum == 1150225935
    assert oat_dex_file.dex_offset == 340324
    assert oat_dex_file.has_dex_file

    # OAT Dex File 2
    oat_dex_file = WallpaperCropper2.oat_dex_files[2]

    assert oat_dex_file.location == "/system/priv-app/WallpaperCropper2/WallpaperCropper2.apk:classes3.dex"
    assert oat_dex_file.checksum == 459332982
    assert oat_dex_file.dex_offset == 1617040
    assert oat_dex_file.has_dex_file

def test_oat_classes():
    WallpaperCropper2 = lief.parse(get_sample("OAT/OAT_064_AArch64_WallpaperCropper2.oat"))
    assert len(WallpaperCropper2.classes) == 1992

    # OAT Class 0
    cls = WallpaperCropper2.get_class("android.support.v4.widget.ViewDragHelper")

    assert cls.fullname == "Landroid/support/v4/widget/ViewDragHelper;"
    assert cls.index == 1066
    assert len(cls.methods) == 49
    assert cls.status == lief.OAT.OAT_CLASS_STATUS.VERIFIED
    assert cls.type == lief.OAT.OAT_CLASS_TYPES.SOME_COMPILED

    # OAT Class 1
    cls = WallpaperCropper2.get_class("com.android.keyguard.KeyguardTransportControlView$SavedState$1")

    assert cls.fullname == "Lcom/android/keyguard/KeyguardTransportControlView$SavedState$1;"
    assert cls.index == 207
    assert len(cls.methods) == 5
    assert cls.status == lief.OAT.OAT_CLASS_STATUS.INITIALIZED
    assert cls.type == lief.OAT.OAT_CLASS_TYPES.ALL_COMPILED

    # OAT Class 2
    cls = WallpaperCropper2.get_class("android.support.v4.os.ParcelableCompatCreatorHoneycombMR2Stub")

    assert cls.fullname == "Landroid/support/v4/os/ParcelableCompatCreatorHoneycombMR2Stub;"
    assert cls.index == 566
    assert len(cls.methods) == 2
    assert cls.status == lief.OAT.OAT_CLASS_STATUS.INITIALIZED
    assert cls.type == lief.OAT.OAT_CLASS_TYPES.ALL_COMPILED

    s = sum(len(cls.methods) for cls in WallpaperCropper2.classes)
    assert len(WallpaperCropper2.methods) == s

    # dex_sum = sum(len(dex.classes) for dex in WallpaperCropper2.dex_files)
    # assert len(WallpaperCropper2.classes) == dex_sum

def test_oat_methods():
    WallpaperCropper2 = lief.parse(get_sample("OAT/OAT_064_AArch64_WallpaperCropper2.oat"))
    assert len(WallpaperCropper2.methods) == 13830

    assert all(m.is_compiled for m in WallpaperCropper2.methods)

    # OAT Method 0
    # ============
    method = WallpaperCropper2.methods[0]
    assert method.name == "<init>"
    assert method.oat_class == WallpaperCropper2.get_class("com/android/gallery3d/ds/DsWallpaperSetting")


    # OAT Method 100
    # ==============
    method = WallpaperCropper2.methods[100]
    assert method.name == "deleteTag"
    assert method.oat_class == WallpaperCropper2.get_class("com/android/gallery3d/exif/ExifInterface")
