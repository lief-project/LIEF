import lief
import json
from utils import get_sample

lief.logging.set_level(lief.logging.LEVEL.INFO)


def test_multidex():
    hangout = lief.parse(get_sample("OAT/OAT_079_AArch64_Hangouts.oat"))

    assert len(hangout.dex_files) == 2

def test_header():
    pm = lief.parse(get_sample("OAT/OAT_079_AArch64_pm.oat"))
    header = pm.header

    assert header.magic == [111, 97, 116, 10]
    assert header.version == 79
    assert header.checksum == 2466303069
    assert header.instruction_set == lief.OAT.INSTRUCTION_SETS.ARM_64
    assert header.nb_dex_files == 1

    assert header.oat_dex_files_offset == 0

    assert header.executable_offset == 73728
    assert header.i2i_bridge_offset == 0
    assert header.i2c_code_bridge_offset == 0
    assert header.jni_dlsym_lookup_offset == 0
    assert header.quick_generic_jni_trampoline_offset == 0
    assert header.quick_imt_conflict_trampoline_offset == 0
    assert header.quick_resolution_trampoline_offset == 0
    assert header.quick_to_interpreter_bridge_offset == 0

    assert header.image_patch_delta == 0

    assert header.image_file_location_oat_checksum == 3334846204
    assert header.image_file_location_oat_data_begin == 1893416960

def test_decompile():
    calldeviceid = lief.parse(get_sample('OAT/OAT_079_x86-64_CallDeviceId.oat'))

    assert len(calldeviceid.dex_files) == 1

    dex2dex_json_info_lhs = json.loads(calldeviceid.dex2dex_json_info)
    dex2dex_json_info_rhs = {'classes.dex': {'Lre/android/art/CallDeviceId;': {'3': {'0': 0}}}}
    assert dex2dex_json_info_lhs == dex2dex_json_info_rhs

def test_dex_files():
    CallDeviceId = lief.parse(get_sample("OAT/OAT_079_x86-64_CallDeviceId.oat"))
    dex_files = CallDeviceId.dex_files

    assert len(dex_files) == CallDeviceId.header.nb_dex_files

    # Dex File 0
    dex = dex_files[0]
    assert dex.name == "classes.dex"
    assert dex.location == "/data/local/tmp/CallDeviceId.dex"
    assert len(dex.raw(deoptimize=False)) == dex.header.file_size



def test_oat_dex_files():
    CallDeviceId = lief.parse(get_sample("OAT/OAT_079_x86-64_CallDeviceId.oat"))
    assert len(CallDeviceId.oat_dex_files) == 1

    # OAT Dex File 0
    oat_dex_file = CallDeviceId.oat_dex_files[0]

    assert oat_dex_file.location == "/data/local/tmp/CallDeviceId.dex"
    assert oat_dex_file.checksum == 284645792
    assert oat_dex_file.dex_offset == 1320
    assert oat_dex_file.has_dex_file

def test_oat_classes():
    CallDeviceId = lief.parse(get_sample("OAT/OAT_079_x86-64_CallDeviceId.oat"))
    assert len(CallDeviceId.classes) == 1

    # OAT Class 0
    cls = CallDeviceId.classes[0]

    assert cls.fullname == "Lre/android/art/CallDeviceId;"
    assert cls.index == 0
    assert len(cls.methods) == 1
    assert cls.status == lief.OAT.OAT_CLASS_STATUS.INITIALIZED
    assert cls.type == lief.OAT.OAT_CLASS_TYPES.SOME_COMPILED


def test_oat_methods():
    CallDeviceId = lief.parse(get_sample("OAT/OAT_079_x86-64_CallDeviceId.oat"))
    assert len(CallDeviceId.methods) == 1

    assert all(m.is_dex2dex_optimized for m in CallDeviceId.methods)

    # OAT Method 0
    # ============
    method = CallDeviceId.methods[0]
    assert method.name == "getIMEI"
    assert method.oat_class == CallDeviceId.get_class("Lre/android/art/CallDeviceId;")
