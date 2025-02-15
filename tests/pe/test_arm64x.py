"""
Tests related to ARM64X
"""
import lief
import pytest

from pathlib import Path
from textwrap import dedent
from utils import get_sample

def test_ms_win_security():
    input_path = Path(get_sample("PE/win11_arm64x_api-ms-win-security-base-l1-1-0.dll"))
    pe = lief.PE.parse(input_path, lief.PE.ParserConfig.all)
    assert not pe.is_arm64ec
    assert pe.is_arm64x

    assert pe.nested_pe_binary is not None

def test_exception_issue():
    input_path = Path(get_sample("PE/arm64x_ImagingEngine.dll"))
    pe = lief.PE.parse(input_path, lief.PE.ParserConfig.all)

    assert len(pe.exceptions) == 9123

    # Indent regression check
    for e in pe.exceptions:
        assert str(e)

def test_photo():
    input_path = Path(get_sample("PE/arm64x_PhotoViewer.dll"))
    pe = lief.PE.parse(input_path)
    assert not pe.is_arm64ec
    assert pe.is_arm64x

    config = pe.load_configuration

    assert config.size == 0x140
    assert config.characteristics == 0x140
    assert config.security_cookie == 0x0000000180165000
    assert config.cast_guard_os_determined_failure_mode == 0x0000000180107098

    metadata: lief.PE.CHPEMetadataARM64 = config.chpe_metadata
    assert metadata is not None

    assert metadata.version == 2
    assert metadata.code_map_count == 5
    assert metadata.code_map == 0x12dd98

    assert metadata.code_ranges_to_entrypoints == 0x12dbe8
    assert metadata.redirection_metadata == 0x177000
    assert metadata.os_arm64x_dispatch_call_no_redirect == 0x107000
    assert metadata.os_arm64x_dispatch_ret == 0x107008
    assert metadata.os_arm64x_dispatch_call == 0x107018
    assert metadata.os_arm64x_dispatch_icall == 0x107010
    assert metadata.os_arm64x_dispatch_icall_cfg == 0x107020
    assert metadata.alternate_entry_point == 0x78de0
    assert metadata.auxiliary_iat == 0x162000
    assert metadata.code_ranges_to_entry_points_count == 8
    assert metadata.redirection_metadata_count == 8
    assert metadata.get_x64_information_function_pointer == 0x107028
    assert metadata.set_x64_information_function_pointer == 0x107030
    assert metadata.extra_rfe_table == 0x175578
    assert metadata.extra_rfe_table_size == 0x24
    assert metadata.os_arm64x_dispatch_fptr == 0x107038
    assert metadata.auxiliary_iat_copy == 0x1609f8
    assert metadata.auxiliary_delay_import == 0x164000
    assert metadata.auxiliary_delay_import_copy == 0x15c5e0
    assert metadata.bitfield_info == 0

    code_range = metadata.code_ranges
    assert len(code_range) == 5
    assert code_range[0].start == 0x00002000
    assert code_range[0].end == 0x00002080
    assert code_range[0].type == lief.PE.CHPEMetadataARM64.range_entry_t.TYPE.AMD64

    assert code_range[1].start == 0x00003000
    assert code_range[1].end == 0x000754a4
    assert code_range[1].type == lief.PE.CHPEMetadataARM64.range_entry_t.TYPE.ARM64

    assert code_range[2].start == 0x00076000
    assert code_range[2].end == 0x001023ac
    assert code_range[2].type == lief.PE.CHPEMetadataARM64.range_entry_t.TYPE.ARM64EC

    assert str(metadata) == dedent("""\
                      2 Version
               0x107000 Arm64X dispatch call function pointer (no redirection)
               0x107008 Arm64X dispatch return function pointer
               0x107018 Arm64X dispatch call function pointer
               0x107010 Arm64X dispatch indirect call function pointer
               0x107020 Arm64X dispatch indirect call function pointer (with CFG check)
                0x78de0 Arm64X alternative entry point
               0x162000 Arm64X auxiliary import address table
               0x107028 Get x64 information function pointer
               0x107030 Set x64 information function pointer
            0x12dbe8[8] Arm64X x64 code ranges to entry points table
            0x177000[8] Arm64X arm64x redirection metadata table
         0x175578[0x24] Arm64X extra RFE table
               0x107038 Arm64X dispatch function pointer
               0x1609f8 Arm64X copy of auxiliary import address table
               0x164000 Arm64X auxiliary delayload import address table
               0x15c5e0 Arm64X auxiliary delayload import address table copy
                    0x0 Arm64X hybrid image info bitfield
    Address Range:
         AMD64 [0x00002000, 0x00002080]
         ARM64 [0x00003000, 0x000754a4]
       ARM64EC [0x00076000, 0x001023ac]
         AMD64 [0x00103000, 0x00103466]
       ARM64EC [0x00104000, 0x00104050]
    Arm64X Redirection Metadata Table:
      0x00002000 --> 0x0007f120
      0x00002010 --> 0x0007f140
      0x00002020 --> 0x0007f2a0
      0x00002030 --> 0x0007f340
      0x00002040 --> 0x0007f3e0
      0x00002050 --> 0x0007f3f0
      0x00002060 --> 0x0007f3f0
      0x00002070 --> 0x00078de0
    """)

def test_empty_tls():
    input_path = Path(get_sample("PE/win11_arm64x_Windows.Media.Protection.PlayReady.dll"))
    pe = lief.PE.parse(input_path, lief.PE.ParserConfig.all)
    nested = lief.PE.parse(list(pe.nested_pe_binary.write_to_bytes()))
    assert nested.tls.addressof_callbacks == 0x18087a1d8

def test_exceptions():
    input_path = Path(get_sample("PE/win11_arm64x_Windows.Media.Protection.PlayReady.dll"))
    pe = lief.PE.parse(input_path, lief.PE.ParserConfig.all)

    assert len(pe.exceptions) == 11731

    assert len([e for e in pe.exceptions if isinstance(e, lief.PE.RuntimeFunctionX64)]) == 4
    assert len([e for e in pe.exceptions if isinstance(e, lief.PE.RuntimeFunctionAArch64)]) == 11727

    nested_pe = pe.nested_pe_binary

    assert len(nested_pe.exceptions) == 11731
    assert len([e for e in nested_pe.exceptions if isinstance(e, lief.PE.RuntimeFunctionX64)]) == 4
    assert len([e for e in nested_pe.exceptions if isinstance(e, lief.PE.RuntimeFunctionAArch64)]) == 11727
