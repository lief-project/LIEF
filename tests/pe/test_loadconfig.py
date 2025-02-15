#!/usr/bin/env python
import lief
from pathlib import Path
from utils import get_sample
from functools import lru_cache
from textwrap import dedent

@lru_cache(maxsize=1)
def _get_default_config() -> lief.PE.Builder.config_t:
    conf = lief.PE.Builder.config_t()
    conf.load_configuration = True
    return conf

def test_winapp(tmp_path: Path):
    winapp = lief.PE.parse(get_sample('PE/PE64_x86-64_binary_WinApp.exe'))
    assert winapp.has_configuration

    lconf = winapp.load_configuration

    assert lconf.characteristics == 0xF8
    assert lconf.timedatestamp == 0
    assert lconf.major_version == 0
    assert lconf.minor_version == 0
    assert lconf.global_flags_clear == 0
    assert lconf.global_flags_set == 0
    assert lconf.critical_section_default_timeout == 0
    assert lconf.decommit_free_block_threshold == 0
    assert lconf.decommit_total_free_threshold == 0
    assert lconf.lock_prefix_table == 0
    assert lconf.maximum_allocation_size == 0
    assert lconf.virtual_memory_threshold == 0
    assert lconf.process_affinity_mask == 0
    assert lconf.process_heap_flags == 0
    assert lconf.csd_version == 0
    assert lconf.reserved1 == 0
    assert lconf.editlist == 0
    assert lconf.security_cookie == 0x14000d008

    # V0
    assert lconf.se_handler_table == 0
    assert lconf.se_handler_count == 0

    # V1
    assert lconf.guard_cf_check_function_pointer == 0x140012000
    assert lconf.guard_cf_dispatch_function_pointer == 0x140012010
    assert lconf.guard_cf_function_table == 0x140011000
    assert lconf.guard_cf_function_count == 15

    expected_flags = lief.PE.LoadConfiguration.IMAGE_GUARD.CF_LONGJUMP_TABLE_PRESENT
    expected_flags |= lief.PE.LoadConfiguration.IMAGE_GUARD.CF_FUNCTION_TABLE_PRESENT
    expected_flags |= lief.PE.LoadConfiguration.IMAGE_GUARD.CF_INSTRUMENTED

    assert lconf.guard_flags == expected_flags

    # V2
    code_integrity = lconf.code_integrity

    assert code_integrity.flags == 0
    assert code_integrity.catalog == 0
    assert code_integrity.catalog_offset == 0
    assert code_integrity.reserved == 0

    assert print(code_integrity) is None

    # V3
    assert lconf.guard_address_taken_iat_entry_table == 0
    assert lconf.guard_address_taken_iat_entry_count == 0
    assert lconf.guard_long_jump_target_table == 0
    assert lconf.guard_long_jump_target_count == 0

    # V4
    assert lconf.dynamic_value_reloc_table == 0
    assert lconf.hybrid_metadata_pointer == 0

    # V5
    assert lconf.guard_rf_failure_routine == 0x140001040
    assert lconf.guard_rf_failure_routine_function_pointer == 0x140012020
    assert lconf.dynamic_value_reloctable_offset == 0
    assert lconf.dynamic_value_reloctable_section == 0
    assert lconf.reserved2 == 0

    # V6
    assert lconf.guard_rf_verify_stackpointer_function_pointer == 0x140012030
    assert lconf.hotpatch_table_offset == 0

    assert print(lconf) is None

    output = tmp_path / "winapp.exe"
    winapp.write(output.as_posix(), _get_default_config())

    new = lief.PE.parse(output)
    assert new.load_configuration == lconf

def test_v8(tmp_path: Path):
    pe = lief.PE.parse(get_sample('PE/ANCUtility.dll'))
    assert pe.has_configuration

    lconf = pe.load_configuration

    assert lconf.volatile_metadata_pointer == 0

    assert print(lconf) is None

    output = tmp_path / "ANCUtility.dll"
    pe.write(output.as_posix(), _get_default_config())

    new = lief.PE.parse(output)
    assert new.load_configuration == lconf

def test_v9(tmp_path: Path):
    pe = lief.PE.parse(get_sample('PE/ucrtbase.dll'))
    assert pe.has_configuration

    lconf = pe.load_configuration

    assert lconf.guard_eh_continuation_table == 0x1800b9770
    assert lconf.guard_eh_continuation_count == 34

    assert print(lconf) is None

    output = tmp_path / "ucrtbase.dll"
    pe.write(output.as_posix())

    new = lief.PE.parse(output)
    assert new.load_configuration == lconf

def test_v11(tmp_path: Path):
    pe = lief.PE.parse(get_sample('PE/hostfxr.dll'))
    assert pe.has_configuration

    lconf = pe.load_configuration

    assert lconf.guard_xfg_check_function_pointer == 0x1800414d8
    assert lconf.guard_xfg_dispatch_function_pointer == 0x1800414e8
    assert lconf.guard_xfg_table_dispatch_function_pointer == 0x1800414f0
    assert lconf.cast_guard_os_determined_failure_mode == 0x180057e18

    assert print(lconf) is None

    assert lconf.copy() == lconf

    output = tmp_path / "hostfxr.dll"
    pe.write(output.as_posix(), _get_default_config())

    new = lief.PE.parse(output)
    assert new.load_configuration == lconf

def test_pgo(tmp_path: Path):
    input_path = Path(get_sample('PE/PE32_x86_binary_PGO-LTCG.exe'))
    pe = lief.PE.parse(input_path)
    lconf = pe.load_configuration
    lconf.security_cookie = 0xdeadc0de
    output = tmp_path / input_path.name
    pe.write(output.as_posix(), _get_default_config())

    new = lief.PE.parse(output)
    assert new.load_configuration.security_cookie == 0xdeadc0de

def test_seh_functions():
    input_path = Path(get_sample("PE/alink.dll"))
    pe = lief.PE.parse(input_path)
    lconfig = pe.load_configuration
    assert lconfig.se_handler_count == 9
    assert lconfig.se_handler_table == 0x100049C4
    functions = pe.load_configuration.seh_functions
    assert len(functions) == 9

    assert functions[0] == 0x00016BE0
    assert functions[8] == 0x000191A5

def test_guard_cf_functions():
    input_path = Path(get_sample("PE/alink.dll"))
    pe = lief.PE.parse(input_path)
    lconfig = pe.load_configuration
    assert lconfig.guard_cf_function_count == 164
    functions = pe.load_configuration.guard_cf_functions
    assert len(functions) == 164

    assert functions[0].rva == 0x00004e90
    assert functions[0].extra == 0

    assert functions[10].rva == 0x00004fa0
    assert functions[10].extra == 2

    assert functions[12].rva == 0x00005050
    assert functions[12].extra == 2

    assert functions[163].rva == 0x00019300
    assert functions[163].extra == 0

def test_guard_cf_iat_taken():
    input_path = Path(get_sample("PE/win11_arm64x_Windows.Media.Protection.PlayReady.dll"))
    pe = lief.PE.parse(input_path)
    lconfig = pe.load_configuration
    assert len(lconfig.guard_address_taken_iat_entries) == 10

    functions = lconfig.guard_address_taken_iat_entries
    assert functions[0].rva == 0x0000000000879008
    assert functions[9].rva == 0x0000000000879050

def test_guard_eh_cont_table():
    input_path = Path(get_sample("PE/win11_arm64x_Windows.Media.Protection.PlayReady.dll"))
    pe = lief.PE.parse(input_path)
    lconfig = pe.load_configuration
    assert len(lconfig.guard_eh_continuation_functions) == 30

    functions = lconfig.guard_eh_continuation_functions
    assert functions[0].rva == 0x0000D5138
    assert functions[29].rva == 0x00057BAEC

def test_long_jump():
    input_path = Path(get_sample("PE/Solitaire.exe"))
    pe = lief.PE.parse(input_path)

    assert not pe.is_arm64x

    lconfig = pe.load_configuration

    assert len(lconfig.guard_long_jump_targets) == 22
    assert lconfig.guard_long_jump_targets[0].rva == 0x0007E1448
    assert lconfig.guard_long_jump_targets[21].rva == 0x000CFB958

def test_dynamic_relocations_1():
    """Test the IMAGE_DYNAMIC_RELOCATION_ARM64_KERNEL_IMPORT_CALL_TRANSFER fixups"""
    input_path = Path(get_sample("PE/winsetupmon.sys"))
    pe = lief.PE.parse(input_path)
    dyn_relocs = pe.load_configuration.dynamic_relocations
    assert len(dyn_relocs) == 2

    relocs_0: lief.PE.DynamicRelocationV1 = dyn_relocs[0] # type: ignore
    assert isinstance(relocs_0, lief.PE.DynamicRelocationV1)
    assert relocs_0.version == 1
    fixups: lief.PE.FunctionOverride = relocs_0.fixups # type: ignore
    assert isinstance(fixups, lief.PE.FunctionOverride)

    relocs_1: lief.PE.DynamicRelocationV1 = dyn_relocs[1] # type: ignore
    assert isinstance(relocs_1, lief.PE.DynamicRelocationV1)
    assert relocs_1.version == 1
    fixups: lief.PE.DynamicFixupARM64Kernel = relocs_1.fixups # type: ignore
    assert isinstance(fixups, lief.PE.DynamicFixupARM64Kernel)

    assert len(fixups.relocations) == 878
    assert fixups.relocations[0].rva == 0x1180
    assert fixups.relocations[0].register_index == 8
    assert fixups.relocations[0].indirect_call
    assert fixups.relocations[0].import_type == lief.PE.DynamicFixupARM64Kernel.IMPORT_TYPE.STATIC
    assert fixups.relocations[0].iat_index == 102

    assert str(fixups.relocations[0]) == dedent("""\
    RVA: 0x00001180 Instr: blr x8   delayload: false IAT index: 0102""")

    assert str(fixups.relocations[1]) == dedent("""\
    RVA: 0x000011b4 Instr: br x16   delayload: false IAT index: 0060""")

    assert str(fixups.relocations[877]) == dedent("""\
    RVA: 0x0002360c Instr: blr x8   delayload: false IAT index: 0074""")

def test_dynamic_relocations_2():
    """Test the IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE fixups"""

    input_path = Path(get_sample("PE/winsetupmon.sys"))
    pe = lief.PE.parse(input_path)
    dyn_relocs = pe.load_configuration.dynamic_relocations
    assert len(dyn_relocs) == 2
    relocs_0: lief.PE.DynamicRelocationV1 = dyn_relocs[0] # type: ignore
    assert isinstance(relocs_0, lief.PE.DynamicRelocationV1)
    assert relocs_0.version == 1
    fixups: lief.PE.FunctionOverride = relocs_0.fixups # type: ignore
    assert isinstance(fixups, lief.PE.FunctionOverride)

    assert len(fixups.func_overriding_info) == 5
    assert len(fixups.bdd_info) == 5
    info = fixups.func_overriding_info[0]
    assert info.bdd_offset == 0
    assert info.original_rva == 0x00010360
    assert info.rva_size == 4
    assert info.base_reloc_size == 0x148

    assert len(info.functions_rva) == 1
    assert info.functions_rva[0] == 0x00010360
    assert len(info.relocations) == 13
    assert info.relocations[0].virtual_address == 0x00001000
    assert len(info.relocations[0].entries) == 34

    assert info.relocations[12].virtual_address == 0x00023000
    assert len(info.relocations[12].entries) == 2

def test_dynamic_relocations_3():
    """Test the IMAGE_DYNAMIC_RELOCATION_ARM64X fixups"""

    input_path = Path(get_sample("PE/win11_arm64x_Windows.Media.Protection.PlayReady.dll"))
    pe = lief.PE.parse(input_path)
    dyn_relocs = pe.load_configuration.dynamic_relocations

    assert len(dyn_relocs) == 2
    relocs_0: lief.PE.DynamicRelocationV1 = dyn_relocs[0] # type: ignore
    assert isinstance(relocs_0, lief.PE.DynamicRelocationV1)

    assert relocs_0.version == 1
    fixups: lief.PE.DynamicFixupARM64X = relocs_0.fixups # type: ignore
    assert isinstance(fixups, lief.PE.DynamicFixupARM64X)

    assert len(fixups.relocations) == 273

    assert fixups.relocations[0].rva == 0x0000010C
    assert fixups.relocations[0].type == lief.PE.DynamicFixupARM64X.FIXUP_TYPE.VALUE
    assert fixups.relocations[0].size == 2
    assert fixups.relocations[0].raw_bytes == [100, 134]

    assert fixups.relocations[0x2f].rva == 0x4ce0b4
    assert fixups.relocations[0x2f].type == lief.PE.DynamicFixupARM64X.FIXUP_TYPE.VALUE
    assert fixups.relocations[0x2f].size == 4
    assert fixups.relocations[0x2f].raw_bytes == [208, 69, 0, 144]

    assert fixups.relocations[272].rva == 0xd83098
    assert fixups.relocations[272].type == lief.PE.DynamicFixupARM64X.FIXUP_TYPE.ZEROFILL
    assert fixups.relocations[272].size == 8

    assert fixups.relocations[262].rva == 0x00d81a70
    assert fixups.relocations[262].type == lief.PE.DynamicFixupARM64X.FIXUP_TYPE.DELTA
    assert fixups.relocations[262].size == 8
    assert fixups.relocations[262].value == 16

def test_dynamic_relocations_4():
    """Test the generic fixups"""
    input_path = Path(get_sample("PE/ntoskrnl.exe"))
    pe = lief.PE.parse(input_path)
    dyn_relocs = pe.load_configuration.dynamic_relocations

    assert len(dyn_relocs) == 12

    ctrl_transfer: lief.PE.DynamicFixupControlTransfer = dyn_relocs[0].fixups # type: ignore
    assert isinstance(ctrl_transfer, lief.PE.DynamicFixupControlTransfer)

    assert len(ctrl_transfer.relocations) == 384
    assert ctrl_transfer.relocations[0].rva == 0x0032baa1
    assert ctrl_transfer.relocations[0].is_call
    assert ctrl_transfer.relocations[0].iat_index == 190

    assert ctrl_transfer.relocations[1].rva == 0x0037e7ae
    assert ctrl_transfer.relocations[1].is_call
    assert ctrl_transfer.relocations[1].iat_index == 65535

    assert ctrl_transfer.relocations[11].rva == 0x003d3ce0
    assert not ctrl_transfer.relocations[11].is_call
    assert ctrl_transfer.relocations[11].iat_index == 122

    assert ctrl_transfer.relocations[383].rva == 0x00b8c2b5
    assert ctrl_transfer.relocations[383].is_call
    assert ctrl_transfer.relocations[383].iat_index == 69

    assert dyn_relocs[11].symbol == 0xfffff6ffffffffff
    generic: lief.PE.DynamicFixupGeneric = dyn_relocs[11].fixups # type: ignore
    assert isinstance(generic, lief.PE.DynamicFixupGeneric)

    assert len(generic.relocations) == 91
    assert generic.relocations[0].virtual_address == 0x00215000

def test_enclave_config():
    input_path = Path(get_sample("PE/SFAPE.dll"))
    pe = lief.PE.parse(input_path)
    assert pe.load_configuration.enclave_configuration_ptr == 0x18000A910
    config = pe.load_configuration.enclave_config
    assert config is not None
    assert config.size == 0x50
    assert config.min_required_config_size == 0x4C
    assert config.policy_flags == 0
    assert not config.is_debuggable
    assert config.nb_imports == 3
    assert config.import_list_rva == 0xB0E8
    assert config.import_entry_size == 0x50
    assert config.image_version == 1
    assert config.security_version == 1
    assert config.enclave_size == 0x1000000
    assert config.nb_threads == 0xA
    assert config.enclave_flags == 1
    assert config.family_id == [
        0x5F, 0xF0, 0xDC, 0xE5, 0x1C, 0x96, 0x4C, 0x5F, 0xA4, 0x5D, 0x89, 0x1C,
        0x44, 0x35, 0x47, 0xAC
    ]
    assert config.image_id == [
        0x5F, 0x10, 0x5D, 0xA3, 0x6B, 0x7B, 0x40, 0x32, 0xBC, 0xAC, 0x0D, 0x2F,
        0x4E, 0x11, 0x40, 0x10
    ]

    assert len(config.imports) == 3
    assert config.imports[0].min_security_version == 0
    assert config.imports[0].reserved == 0
    assert config.imports[0].type == lief.PE.EnclaveImport.TYPE.IMAGE_ID
    assert config.imports[0].family_id == [0] * 16
    assert config.imports[0].id == [0] * 32
    assert config.imports[0].image_id == [
        0xF0, 0x3C, 0xCD, 0xA7, 0xE8, 0x7B, 0x46, 0xEB, 0xAA, 0xE7, 0x1F, 0x13,
        0xD5, 0xCD, 0xDE, 0x5D
    ]

    assert dedent(str(config)) == dedent("""\
                                    Size: 0x00000050
            Minimum Required Config Size: 0x0000004c
                            Policy Flags: 0x00000000 (debuggable=false)
    Number of Enclave Import Descriptors: 3
                  RVA to enclave imports: 0x0000b0e8
                  Size of enclave import: 0x0050
                           Image version: 1
                        Security version: 1
                            Enclave Size: 0x0000000001000000
                       Number of Threads: 10
                           Enclave flags: 0x00000001
                                Image ID: 5f 10 5d a3 6b 7b 40 32 bc ac 0d 2f 4e 11 40 10
                               Family ID: 5f f0 dc e5 1c 96 4c 5f a4 5d 89 1c 44 35 47 ac
     ucrtbase_enclave.dll (RVA: 0x0000c0e2)
       Minimum Security Version  : 0
       Reserved                  : 0
       Type                      : IMAGE_ID
       Family ID                 : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
       Image ID                  : f0 3c cd a7 e8 7b 46 eb aa e7 1f 13 d5 cd de 5d
       unique/author ID          : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                                   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

     bcrypt.dll (RVA: 0x0000c1c6)
       Minimum Security Version  : 0
       Reserved                  : 0
       Type                      : IMAGE_ID
       Family ID                 : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
       Image ID                  : 20 27 bd 68 75 59 49 b7 be 06 34 50 e2 16 d7 ed
       unique/author ID          : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                                   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

     vertdll.dll (RVA: 0x0000c2ce)
       Minimum Security Version  : 0
       Reserved                  : 0
       Type                      : IMAGE_ID
       Family ID                 : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
       Image ID                  : 72 84 41 72 67 a8 4e 8d bf 01 28 4b 07 43 2b 1e
       unique/author ID          : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                                   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

    """)

def test_volatile_metadata():
    input_path = Path(get_sample("PE/LIEF-win64.dll"))
    pe = lief.PE.parse(input_path)
    assert pe.load_configuration.volatile_metadata_pointer == 0x180383894
    metadata = pe.load_configuration.volatile_metadata

    assert metadata.size == 0x18
    assert metadata.min_version == 0x8003
    assert metadata.max_version == 0x8003
    assert metadata.access_table_rva == 0x003838ac
    assert metadata.access_table_size == 2500
    assert metadata.info_range_rva == 0x00384270
    assert metadata.info_ranges_size == 56

    assert len(metadata.access_table) == 625
    assert len(metadata.info_ranges) == 7

    assert metadata.access_table[0] == 0x00001c37
    assert metadata.access_table[624] == 0x002c1b4c

    assert metadata.info_ranges[0].start == 0x00001000
    assert metadata.info_ranges[0].end == 0x002a9d55

    assert metadata.info_ranges[6].start == 0x002abef0
    assert metadata.info_ranges[6].end == 0x002c23bb
