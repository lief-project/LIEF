#!/usr/bin/env python
import lief
import pytest
from utils import get_sample, has_private_samples
import hashlib

def test_function_starts():
    dd = lief.MachO.parse(get_sample('MachO/MachO64_x86-64_binary_dd.bin')).at(0)

    functions = [
        0x100001581, 0x1000016cc, 0x1000017cc,
        0x1000019e3, 0x100001a03, 0x100001a1d,
        0x1000020ad, 0x1000022f6, 0x1000023ef,
        0x10000246b, 0x10000248c, 0x1000026da,
        0x100002754, 0x10000286b, 0x100002914,
        0x100002bd8, 0x100002be8, 0x100002c2b,
        0x100002c62, 0x100002d24, 0x100002d5a,
        0x100002d91, 0x100002dd5, 0x100002de6,
        0x100002dfc, 0x100002e40, 0x100002e51,
        0x100002e67, 0x100002f9e
    ]

    assert dd.function_starts.data_offset == 21168
    assert dd.function_starts.data_size == 48
    text_segment = list(filter(lambda e: e.name == "__TEXT", dd.segments))[0]
    functions_dd = map(text_segment.virtual_address .__add__, dd.function_starts.functions)

    assert functions == list(functions_dd)


def test_version_min():
    sshd = lief.MachO.parse(get_sample('MachO/MachO64_x86-64_binary_sshd.bin')).at(0)
    assert sshd.version_min.version == [10, 11, 0]
    assert sshd.version_min.sdk == [10, 11, 0]

def test_va2offset():
    dd = lief.MachO.parse(get_sample('MachO/MachO64_x86-64_binary_dd.bin')).at(0)
    assert dd.virtual_address_to_offset(0x100004054) == 0x4054


def test_thread_cmd():
    micromacho = lief.MachO.parse(get_sample('MachO/MachO32_x86_binary_micromacho.bin')).at(0)
    assert micromacho.has_thread_command
    assert micromacho.thread_command.pc == 0x68
    assert micromacho.thread_command.flavor == 1
    assert micromacho.thread_command.count == 16
    assert micromacho.entrypoint == 0x68

def test_rpath_cmd():
    rpathmacho = lief.MachO.parse(get_sample('MachO/MachO64_x86-64_binary_rpathtest.bin')).at(0)
    assert rpathmacho.rpath.path == "@executable_path/../lib"

def test_rpaths():
    macho = lief.MachO.parse(get_sample('MachO/rpath_291.bin')).at(0)
    assert len(macho.rpaths) == 2

    assert macho.rpaths[0].path == "/tmp"
    assert macho.rpaths[1].path == "/var"

def test_relocations():
    helloworld = lief.MachO.parse(get_sample('MachO/MachO64_x86-64_object_HelloWorld64.o')).at(0)

    # __text Section
    text_section = helloworld.get_section("__text")
    relocations  = text_section.relocations
    assert len(relocations) == 2

    # 1
    assert relocations[0].address == 0x233
    assert relocations[0].type ==    2
    assert relocations[0].size ==    32

    assert not relocations[0].is_scattered # type: ignore[attr-defined]

    assert relocations[0].has_symbol
    assert relocations[0].symbol.name == "_printf"

    assert relocations[0].has_section
    assert relocations[0].section.name == text_section.name

    # 0
    assert relocations[1].address == 0x21b
    assert relocations[1].type ==    1
    assert relocations[1].size ==    32

    assert not relocations[1].is_scattered # type: ignore[attr-defined]

    assert not relocations[1].has_symbol

    assert relocations[1].has_section
    assert relocations[1].section.name == text_section.name


    # __compact_unwind__LD  Section
    cunwind_section = helloworld.get_section("__compact_unwind")
    relocations  = cunwind_section.relocations
    assert len(relocations) == 1

    # 0
    assert relocations[0].address == 0x247
    assert relocations[0].type ==    0
    assert relocations[0].size ==    32

    assert not relocations[0].is_scattered # type: ignore[attr-defined]

    assert not relocations[0].has_symbol

    assert relocations[0].has_section
    assert relocations[0].section.name == "__cstring"

def test_data_in_code():
    binary = lief.MachO.parse(get_sample('MachO/MachO32_ARM_binary_data-in-code-LLVM.bin')).at(0)

    assert binary.has_data_in_code
    dcode = binary.data_in_code

    assert dcode.data_offset == 0x11c
    assert dcode.data_size == 0x20

    assert len(dcode.entries) == 4

    assert dcode.entries[0].type == lief.MachO.DataCodeEntry.TYPES.DATA
    assert dcode.entries[0].offset == 0
    assert dcode.entries[0].length == 4

    assert dcode.entries[1].type == lief.MachO.DataCodeEntry.TYPES.JUMP_TABLE_32
    assert dcode.entries[1].offset == 4
    assert dcode.entries[1].length == 4

    assert dcode.entries[2].type == lief.MachO.DataCodeEntry.TYPES.JUMP_TABLE_16
    assert dcode.entries[2].offset == 8
    assert dcode.entries[2].length == 2

    assert dcode.entries[3].type == lief.MachO.DataCodeEntry.TYPES.JUMP_TABLE_8
    assert dcode.entries[3].offset == 10
    assert dcode.entries[3].length == 1


def test_segment_split_info():
    binary = lief.MachO.parse(get_sample('MachO/FAT_MachO_x86_x86-64_library_libdyld.dylib')).at(1)

    assert binary.has_segment_split_info
    ssi = binary.segment_split_info
    assert ssi.data_offset == 32852
    assert ssi.data_size == 292

def test_dyld_environment():
    binary = lief.MachO.parse(get_sample('MachO/MachO64_x86-64_binary_safaridriver.bin')).at(0)
    assert binary.has_dyld_environment
    assert binary.dyld_environment.value == "DYLD_VERSIONED_FRAMEWORK_PATH=/System/Library/StagedFrameworks/Safari"

def test_sub_framework():
    binary = lief.MachO.parse(get_sample('MachO/FAT_MachO_x86_x86-64_library_libdyld.dylib')).at(0)
    assert binary.has_sub_framework
    assert binary.sub_framework.umbrella == "System"

def test_unwind():
    binary = lief.MachO.parse(get_sample('MachO/MachO64_x86-64_binary_sshd.bin')).at(0)

    functions = sorted(binary.functions, key=lambda f: f.address)

    assert len(functions) == 2619

    assert functions[0].address == 2624
    assert functions[0].size    == 0
    assert functions[0].name    == ""

    assert functions[-1].address == 0x1000a4f65
    assert functions[-1].size    == 0
    assert functions[-1].name    == "ctor_0"


def test_build_version():
    binary = lief.MachO.parse(get_sample('MachO/FAT_MachO_arm-arm64-binary-helloworld.bin'))
    target = binary[1]

    assert target.has_build_version
    build_version = target.build_version

    assert build_version.minos == [12, 1, 0]
    assert build_version.sdk ==   [12, 1, 0]
    assert build_version.platform == lief.MachO.BuildVersion.PLATFORMS.IOS

    tools = build_version.tools
    assert len(tools) == 1
    assert tools[0].version == [409, 12, 0]
    assert tools[0].tool == lief.MachO.BuildToolVersion.TOOLS.LD

def test_segment_index():
    binary = lief.MachO.parse(get_sample('MachO/MachO64_x86-64_binary_safaridriver.bin')).at(0)
    assert binary.get_segment("__LINKEDIT").index == len(binary.segments) - 1
    original_data_index = binary.get_segment("__DATA").index

    # Add a new segment (it should be placed right beore __LINKEDIT)
    segment = lief.MachO.SegmentCommand("__LIEF", [0x60] * 0x100)
    segment = binary.add(segment) # type: ignore[assignment]
    assert segment.index == binary.get_segment("__LINKEDIT").index - 1
    assert segment.index == original_data_index + 1

    # discard changes
    binary = lief.MachO.parse(get_sample('MachO/MachO64_x86-64_binary_safaridriver.bin')).at(0)
    text_segment = binary.get_segment("__TEXT")
    original_data_index = binary.get_segment("__DATA").index

    binary.remove(text_segment)
    assert binary.get_segment("__DATA").index == original_data_index - 1
    assert binary.get_segment("__LINKEDIT").index == original_data_index
    assert binary.get_segment("__PAGEZERO").index == 0

def test_offset_to_va():

    # |Name        |Virtual Address|Virtual Size|Offset|Size
    # +------------+---------------+------------+------+----
    # |__PAGEZERO  |0x0            |0x100000000 |0x0   |0x0
    # |__TEXT      |0x100000000    |0x4000      |0x0   |0x4000
    # |__DATA_CONST|0x100004000    |0x4000      |0x4000|0x4000
    # |__DATA      |0x100008000    |0x8000      |0x8000|0x4000
    # |__LINKEDIT  |0x100010000    |0x4000      |0xc000|0x130

    sample = get_sample("MachO/MachO64_x86-64_binary_large-bss.bin")
    large_bss = lief.MachO.parse(sample).at(0)
    assert large_bss.segment_from_offset(0).name      == "__TEXT"
    assert large_bss.segment_from_offset(0x4001).name == "__DATA_CONST"
    assert large_bss.segment_from_offset(0xc000).name == "__LINKEDIT"
    assert large_bss.segment_from_offset(0xc001).name == "__LINKEDIT"


def test_get_section():
    sample = get_sample("MachO/MachO64_x86-64_binary_large-bss.bin")
    macho = lief.MachO.parse(sample).at(0)
    assert macho.get_section("__DATA_CONST", "__got") is not None



def test_segment_add_section():
    binary = lief.MachO.parse(get_sample('MachO/MachO64_x86-64_binary_safaridriver.bin')).at(0)

    section = lief.MachO.Section("__bar", [1, 2, 3])

    existing_segment = binary.get_segment("__TEXT")
    new_segment = lief.MachO.SegmentCommand("__FOO")

    for segment in (existing_segment, new_segment):
        assert not segment.has_section(section.name) # type: ignore[arg-type]
        assert not segment.has(section)
        assert segment.numberof_sections == len(segment.sections)

        numberof_sections = segment.numberof_sections

        section = segment.add_section(section)
        assert segment.numberof_sections == numberof_sections + 1
        assert segment.has_section(section.name) # type: ignore[arg-type]
        assert segment.has(section)
        assert section in segment.sections

def test_issue_728():
    x86_64_binary = lief.MachO.parse(get_sample('MachO/MachO64_x86-64_binary_safaridriver.bin')).at(0)
    arm64_binary = lief.MachO.parse(get_sample('MachO/FAT_MachO_arm-arm64-binary-helloworld.bin')).take(lief.MachO.Header.CPU_TYPE.ARM64)

    segment = lief.MachO.SegmentCommand("__FOO")
    segment.add_section(lief.MachO.Section("__bar", [1, 2, 3]))

    for parsed in (x86_64_binary, arm64_binary):
        new_segment = parsed.add(segment)
        assert new_segment.virtual_size == parsed.page_size

def test_twolevel_hints():
    sample = lief.MachO.parse(get_sample("MachO/ios1-expr.bin"))[0]
    tw_hints: lief.MachO.TwoLevelHints = sample[lief.MachO.LoadCommand.TYPE.TWOLEVEL_HINTS]
    assert tw_hints is not None
    print(tw_hints)
    hints = tw_hints.hints
    assert len(hints) == 26
    print(hints[0])
    assert sum(hints) == 10854400
    assert hints[0] == 54528
    assert hashlib.sha256(tw_hints.data).hexdigest() == "e44cef3a83eb89954557a9ad2a36ebf4794ce0385da5a39381fdadc3e6037beb"
    assert tw_hints.command_offset == 1552
    print(lief.to_json(tw_hints))

def test_overlay():
    sample = lief.MachO.parse(get_sample("MachO/overlay_data.bin")).at(0)
    assert bytes(sample.overlay) == b'\x00overlay data'

def test_issue_1055():
    sample = lief.MachO.parse(get_sample("MachO/issue_1055.bin")).at(0)
    for section in sample.sections:
        size = len(section.content)
        assert size is not None

def test_unknown_command():
    sample = lief.MachO.parse(get_sample("MachO/libadd_unknown_cmd.so")).at(0)
    unknown_cmd = sample.commands[15]
    assert isinstance(unknown_cmd, lief.MachO.UnknownCommand)
    assert unknown_cmd.original_command == 0x3333
    print(hash(unknown_cmd))
    print(unknown_cmd)

@pytest.mark.skipif(not has_private_samples(), reason="needs private samples")
def test_arm64e():
    sample = lief.MachO.parse(get_sample("private/MachO/libCoreKE_arm64e.dylib")).at(0)
    assert sample.support_arm64_ptr_auth
