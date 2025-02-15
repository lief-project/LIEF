"""
Tests related to ARM64EC
"""
import lief
import pytest

from pathlib import Path
from textwrap import dedent
from utils import get_sample, has_private_samples

def test_chpe_simple():
    input_path = Path(get_sample("PE/arm64ec_hello_world_2025.exe"))
    pe = lief.PE.parse(input_path)

    config = pe.load_configuration
    assert config.hybrid_metadata_pointer == 0x1400111f8
    assert config.guard_memcpy_function_pointer == 0x1400110a0

    metadata: lief.PE.CHPEMetadataARM64 = config.chpe_metadata
    assert metadata is not None
    assert isinstance(metadata, lief.PE.CHPEMetadataARM64)

    assert metadata.version == 2
    assert metadata.code_map_count == 2
    assert metadata.code_map == 0x11e00

    assert metadata.code_ranges_to_entrypoints == 0x11cb4
    assert metadata.redirection_metadata == 0x19000
    assert metadata.os_arm64x_dispatch_call_no_redirect == 0x11000
    assert metadata.os_arm64x_dispatch_ret == 0x11008
    assert metadata.os_arm64x_dispatch_call == 0x11018
    assert metadata.os_arm64x_dispatch_icall == 0x11010
    assert metadata.os_arm64x_dispatch_icall_cfg == 0x11020
    assert metadata.alternate_entry_point == 0
    assert metadata.auxiliary_iat == 0x15000
    assert metadata.code_ranges_to_entry_points_count == 1
    assert metadata.redirection_metadata_count == 1
    assert metadata.get_x64_information_function_pointer == 0x11028
    assert metadata.set_x64_information_function_pointer == 0x11030
    assert metadata.extra_rfe_table == 0x17000
    assert metadata.extra_rfe_table_size == 0xd38
    assert metadata.os_arm64x_dispatch_fptr == 0x11038
    assert metadata.auxiliary_iat_copy == 0x13e48
    assert metadata.auxiliary_delay_import == 0
    assert metadata.auxiliary_delay_import_copy == 0
    assert metadata.bitfield_info == 0

    code_range = metadata.code_ranges
    assert len(code_range) == 2
    assert code_range[0].start == 0x00001000
    assert code_range[0].end == 0x0000d4c8
    assert code_range[0].type == lief.PE.CHPEMetadataARM64.range_entry_t.TYPE.ARM64EC

    assert code_range[1].start == 0x0000e000
    assert code_range[1].end == 0x0000f010
    assert code_range[1].type == lief.PE.CHPEMetadataARM64.range_entry_t.TYPE.AMD64

    redirections = metadata.redirections
    assert redirections[0].src == 0x0000f000
    assert redirections[0].dst == 0x00006ac8

    assert str(metadata) == dedent("""\
                      2 Version
                0x11000 Arm64X dispatch call function pointer (no redirection)
                0x11008 Arm64X dispatch return function pointer
                0x11018 Arm64X dispatch call function pointer
                0x11010 Arm64X dispatch indirect call function pointer
                0x11020 Arm64X dispatch indirect call function pointer (with CFG check)
                    0x0 Arm64X alternative entry point
                0x15000 Arm64X auxiliary import address table
                0x11028 Get x64 information function pointer
                0x11030 Set x64 information function pointer
             0x11cb4[1] Arm64X x64 code ranges to entry points table
             0x19000[1] Arm64X arm64x redirection metadata table
         0x17000[0xd38] Arm64X extra RFE table
                0x11038 Arm64X dispatch function pointer
                0x13e48 Arm64X copy of auxiliary import address table
                    0x0 Arm64X auxiliary delayload import address table
                    0x0 Arm64X auxiliary delayload import address table copy
                    0x0 Arm64X hybrid image info bitfield
    Address Range:
       ARM64EC [0x00001000, 0x0000d4c8]
         AMD64 [0x0000e000, 0x0000f010]
    Arm64X Redirection Metadata Table:
      0x0000f000 --> 0x00006ac8
    """)


def test_exceptions_simple():
    input_path = Path(get_sample("PE/arm64ec_hello_world_2025.exe"))
    pe = lief.PE.parse(input_path, lief.PE.ParserConfig.all)
    assert pe.is_arm64ec
    assert not pe.is_arm64x

    # It contains both x64 / ARM64 exceptions info
    exceptions = pe.exceptions
    assert len(exceptions) == 425

    assert len([
        e for e in pe.exceptions if e.arch == lief.PE.ExceptionInfo.ARCH.X86_64
    ]) == 2
    assert len([
        e for e in pe.exceptions if e.arch == lief.PE.ExceptionInfo.ARCH.ARM64
    ]) == 423

    x64_0: lief.PE.RuntimeFunctionX64 = exceptions[0]
    assert isinstance(x64_0, lief.PE.RuntimeFunctionX64)
    assert x64_0.rva_start == 0x00e2c0
    assert x64_0.unwind_info.count_opcodes == 0

    # Simple/basic entry
    e_basic: lief.PE.unwind_aarch64.UnpackedFunction = pe.find_exception_at(0x00001000)
    assert isinstance(e_basic, lief.PE.unwind_aarch64.UnpackedFunction)
    assert e_basic.rva_start == 0x00001000
    assert e_basic.rva_end == 0x00001018
    assert e_basic.xdata_rva == 0x00012740
    assert e_basic.version == 0
    assert e_basic.X == 0
    assert e_basic.E == 0
    assert e_basic.code_words == 1
    assert e_basic.epilog_count == 1
    assert e_basic.length == 24

    assert len(e_basic.epilog_scopes) == 1
    assert e_basic.epilog_scopes[0].reserved == 0
    assert e_basic.epilog_scopes[0].start_index == 2
    assert e_basic.epilog_scopes[0].start_offset == 5

    assert str(e_basic) == dedent("""\
    Runtime Unpacked AArch64 Function {
      Range(RVA): 0x00001000 - 0x00001018
      Unwind location (RVA): 0x00012740
      Length=24 Vers=0 X=0 E=0, CodeWords=1
      Epilogs=1
      Prolog unwind:
        0x0000 01...... sub sp, #16
        0x0001 e4...... end
      Epilog #1 unwind:  (Offset=5, Index=2, Reserved=0)
        0x0000 e4...... end
    }""")

    # Entry with exception data (X=1)
    entry: lief.PE.unwind_aarch64.UnpackedFunction = pe.find_exception_at(0x00004a90)
    assert isinstance(e_basic, lief.PE.unwind_aarch64.UnpackedFunction)
    assert entry.rva_start == 0x00004a90
    assert entry.X == 1
    assert entry.exception_handler == 0x00004a40

    assert str(entry) == dedent("""\
    Runtime Unpacked AArch64 Function {
      Range(RVA): 0x00004a90 - 0x00004ad4
      Unwind location (RVA): 0x000131b4
      Length=68 Vers=0 X=1 E=0, CodeWords=1
      Exception Handler: 0x00004a40
      Epilogs=0
      Prolog unwind:
        0x0000 e4...... end
    }""")

    # Entry with multiple epilog scopes
    entry: lief.PE.unwind_aarch64.UnpackedFunction = pe.find_exception_at(0x000076a0)
    assert isinstance(e_basic, lief.PE.unwind_aarch64.UnpackedFunction)
    assert entry.rva_start == 0x000076a0
    assert entry.X == 0
    assert entry.epilog_count == 2

    assert len(entry.epilog_scopes) == 2
    assert entry.epilog_scopes[0].reserved == 0
    assert entry.epilog_scopes[0].start_index == 1
    assert entry.epilog_scopes[0].start_offset == 15

    assert entry.epilog_scopes[1].reserved == 0
    assert entry.epilog_scopes[1].start_index == 1
    assert entry.epilog_scopes[1].start_offset == 23

    assert str(entry) == dedent("""\
    Runtime Unpacked AArch64 Function {
      Range(RVA): 0x000076a0 - 0x00007708
      Unwind location (RVA): 0x000129ac
      Length=104 Vers=0 X=0 E=0, CodeWords=1
      Epilogs=2
      Prolog unwind:
        0x0000 e1...... mov fp, sp
        0x0001 81...... stp x29, x30, [sp, #-16]!
        0x0002 fc...... pacibsp
        0x0003 e4...... end
      Epilog #1 unwind:  (Offset=15, Index=1, Reserved=0)
        0x0000 81...... ldp x29, x30, [sp], #16
        0x0001 fc...... autibsp
        0x0002 e4...... end
      Epilog #2 unwind:  (Offset=23, Index=1, Reserved=0)
        0x0000 81...... ldp x29, x30, [sp], #16
        0x0001 fc...... autibsp
        0x0002 e4...... end
    }""")

    # Entry with large epilog (using offset)
    entry: lief.PE.unwind_aarch64.UnpackedFunction = pe.find_exception_at(0x00005658)
    assert isinstance(e_basic, lief.PE.unwind_aarch64.UnpackedFunction)
    assert entry.rva_start == 0x00005658
    assert entry.X == 1
    assert entry.epilog_count == 0
    assert entry.epilog_offset == 0x00000a

    assert str(entry) == dedent("""\
    Runtime Unpacked AArch64 Function {
      Range(RVA): 0x00005658 - 0x00005a50
      Unwind location (RVA): 0x00012478
      Length=1016 Vers=0 X=1 E=1, CodeWords=5
      Exception Handler: 0x00006938
      Epilogs (offset)=0x00000a
      Prolog unwind:
        0x0000 01...... sub sp, #16
        0x0001 e1...... mov fp, sp
        0x0002 d205.... str x27, [sp, #40]
        0x0004 d0c4.... str x22, [sp, #32]
        0x0006 c842.... stp x20, x21, [sp, #16]
        0x0008 85...... stp x29, x30, [sp, #-48]!
        0x0009 e4...... end
      Epilog unwind:
        0x0000 16...... add sp, #352
        0x0001 01...... add sp, #16
        0x0002 d205.... ldr x27, [sp, #40]
        0x0004 d0c4.... ldr x22, [sp, #32]
        0x0006 c842.... ldp x20, x21, [sp, #16]
        0x0008 85...... ldp x29, x30, [sp], #48
        0x0009 e4...... end
    }""")

    # Entry that uses the (undocumented) save any reg opcode
    entry: lief.PE.unwind_aarch64.UnpackedFunction = pe.find_exception_at(0x0000bb48)
    assert str(entry) == dedent("""\
    Runtime Unpacked AArch64 Function {
      Range(RVA): 0x0000bb48 - 0x0000bb98
      Unwind location (RVA): 0x00012328
      Length=80 Vers=0 X=0 E=0, CodeWords=8
      Epilogs=1
      Prolog unwind:
        0x0000 e1...... mov fp, sp
        0x0001 81...... stp x29, x30, [sp, #-16]!
        0x0002 e6...... save next
        0x0003 e6...... save next
        0x0004 e6...... save next
        0x0005 e6...... save next
        0x0006 e76689.. stp q6, q7, [sp, #-160]!
        0x0009 fc...... pacibsp
        0x000a e4...... end
      Epilog #1 unwind:  (Offset=10, Index=11, Reserved=0)
        0x0000 81...... ldp x29, x30, [sp], #16
        0x0001 e74e88.. ldp q14, q15, [sp, #128]
        0x0004 e74c86.. ldp q12, q13, [sp, #96]
        0x0007 e74a84.. ldp q10, q11, [sp, #64]
        0x000a e74882.. ldp q8, q9, [sp, #32]
        0x000d e76689.. ldp q6, q7, [sp], #160
        0x0010 fc...... autibsp
        0x0011 e3...... nop
        0x0012 e3...... nop
        0x0013 e4...... end
    }""")

    # Packed entry
    entry: lief.PE.unwind_aarch64.PackedFunction = pe.find_exception_at(0x0000bea8)
    assert entry.flag == lief.PE.RuntimeFunctionAArch64.PACKED_FLAGS.PACKED
    assert isinstance(entry, lief.PE.unwind_aarch64.PackedFunction)

    assert entry.rva_start == 0x0000bea8
    assert entry.rva_end == 0x0000bed4
    assert entry.length == 44
    assert entry.frame_size == 0x10
    assert entry.reg_F == 0
    assert entry.reg_I == 0
    assert entry.H == 0
    assert entry.CR == 2

def test_unaligned():
    """
    .pdata content is not 8-byte aligned
    """
    input_path = Path(get_sample("PE/win11_arm64ec_Windows_AI_MachineLearning_x64.dll"))
    pe = lief.PE.parse(input_path, lief.PE.ParserConfig.all)
    assert pe.is_arm64ec
    assert not pe.is_arm64x

    assert len(pe.exceptions) == 4457

    assert len([
        e for e in pe.exceptions if e.arch == lief.PE.ExceptionInfo.ARCH.X86_64
    ]) == 7
    assert len([
        e for e in pe.exceptions if e.arch == lief.PE.ExceptionInfo.ARCH.ARM64
    ]) == 4450
