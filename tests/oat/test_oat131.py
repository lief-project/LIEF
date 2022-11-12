import lief
from utils import get_sample

def test_header():
    CallDeviceId = lief.parse(get_sample("OAT/OAT_131_x86_CallDeviceId.oat"))
    header = CallDeviceId.header

    assert header.magic == [111, 97, 116, 10]
    assert header.version == 131
    assert header.checksum == 0x8e82f9b5
    assert header.instruction_set == lief.OAT.INSTRUCTION_SETS.X86
    assert header.nb_dex_files == 1

    assert header.oat_dex_files_offset == 1484

    assert header.executable_offset == 0x1000
    assert header.i2i_bridge_offset == 0
    assert header.i2c_code_bridge_offset == 0
    assert header.jni_dlsym_lookup_offset == 0
    assert header.quick_generic_jni_trampoline_offset == 0
    assert header.quick_imt_conflict_trampoline_offset == 0
    assert header.quick_resolution_trampoline_offset == 0
    assert header.quick_to_interpreter_bridge_offset == 0

    assert header.image_patch_delta == 15335424

    assert header.image_file_location_oat_checksum == 0xdacfe293
    assert header.image_file_location_oat_data_begin == 0x716a9000

def test_oat_dex_files():
    CallDeviceId = lief.parse(get_sample("OAT/OAT_131_x86_CallDeviceId.oat"))
    assert len(CallDeviceId.oat_dex_files) == 1

    # OAT Dex File 0
    oat_dex_file = CallDeviceId.oat_dex_files[0]

    assert oat_dex_file.location == "/data/local/tmp/CallDeviceId.dex"
    assert oat_dex_file.checksum == 284645792
    assert oat_dex_file.dex_offset == 28
    assert not oat_dex_file.has_dex_file

def test_oat_classes():
    oat_file  = get_sample("OAT/OAT_131_x86_CallDeviceId.oat")
    vdex_file = get_sample("VDEX/VDEX_10_x86_CallDeviceId.vdex")

    #oat_file  = get_sample("OAT/OAT_131_AArch64_svc.oat")
    #vdex_file = get_sample("VDEX/VDEX_10_AArch64_svc.vdex")

    CallDeviceId = lief.OAT.parse(oat_file, vdex_file)
    assert len(CallDeviceId.classes) == 1

    # OAT Class 0
    cls = CallDeviceId.classes[0]

    assert cls.fullname == "Lre/android/art/CallDeviceId;"
    assert cls.index == 0
    assert len(cls.methods) == 0
    #assert cls.status == lief.OAT.OAT_CLASS_STATUS.INITIALIZED # TODO
    assert cls.type == lief.OAT.OAT_CLASS_TYPES.NONE_COMPILED

def test_oat_methods():
    oat_file  = get_sample("OAT/OAT_124_x86-64_CallDeviceId.oat")
    vdex_file = get_sample("VDEX/VDEX_06_x86-64_CallDeviceId.vdex")

    CallDeviceId = lief.OAT.parse(oat_file, vdex_file)
    assert len(CallDeviceId.methods) == 1

    assert all(m.is_dex2dex_optimized for m in CallDeviceId.methods)

    # OAT Method 0
    # ============
    method = CallDeviceId.methods[0]
    assert method.name == "getIMEI"
    assert method.oat_class == CallDeviceId.get_class("Lre/android/art/CallDeviceId;")
