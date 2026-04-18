import hashlib
import struct
from pathlib import Path
from typing import cast

import lief
import pytest
from utils import get_sample, parse_macho


def test_function_starts():
    dd = parse_macho("MachO/MachO64_x86-64_binary_dd.bin").at(0)
    assert dd is not None

    functions = [
        0x100001581,
        0x1000016CC,
        0x1000017CC,
        0x1000019E3,
        0x100001A03,
        0x100001A1D,
        0x1000020AD,
        0x1000022F6,
        0x1000023EF,
        0x10000246B,
        0x10000248C,
        0x1000026DA,
        0x100002754,
        0x10000286B,
        0x100002914,
        0x100002BD8,
        0x100002BE8,
        0x100002C2B,
        0x100002C62,
        0x100002D24,
        0x100002D5A,
        0x100002D91,
        0x100002DD5,
        0x100002DE6,
        0x100002DFC,
        0x100002E40,
        0x100002E51,
        0x100002E67,
        0x100002F9E,
    ]

    function_starts = dd.function_starts
    assert function_starts is not None
    assert function_starts.data_offset == 21168
    assert function_starts.data_size == 48
    text_segment = list(filter(lambda e: e.name == "__TEXT", dd.segments))[0]
    functions_dd = map(text_segment.virtual_address.__add__, function_starts.functions)

    assert functions == list(functions_dd)


def test_version_min():
    sshd = parse_macho("MachO/MachO64_x86-64_binary_sshd.bin").at(0)
    assert sshd is not None
    version_min = sshd.version_min
    assert version_min is not None
    assert version_min.version == [10, 11, 0]
    assert version_min.sdk == [10, 11, 0]


def test_va2offset():
    dd = parse_macho("MachO/MachO64_x86-64_binary_dd.bin").at(0)
    assert dd is not None
    assert dd.virtual_address_to_offset(0x100004054) == 0x4054


def test_thread_cmd():
    micromacho = parse_macho("MachO/MachO32_x86_binary_micromacho.bin").at(0)
    assert micromacho is not None
    assert micromacho.has_thread_command
    thread_command = micromacho.thread_command
    assert thread_command is not None
    assert thread_command.pc == 0x68
    assert thread_command.flavor == 1
    assert thread_command.count == 16
    assert micromacho.entrypoint == 0x68


def test_rpath_cmd():
    rpathmacho = parse_macho("MachO/MachO64_x86-64_binary_rpathtest.bin").at(0)
    assert rpathmacho is not None
    rpath = rpathmacho.rpath
    assert rpath is not None
    assert rpath.path == "@executable_path/../lib"
    output = str(rpath)
    assert "@executable_path/../lib" in output
    assert hash(rpath) != 0


def test_rpaths():
    macho = parse_macho("MachO/rpath_291.bin").at(0)
    assert macho is not None
    assert len(macho.rpaths) == 2

    assert macho.rpaths[0].path == "/tmp"
    assert macho.rpaths[1].path == "/var"


def test_relocations():
    helloworld = parse_macho("MachO/MachO64_x86-64_object_HelloWorld64.o").at(0)
    assert helloworld is not None

    # __text Section
    text_section = helloworld.get_section("__text")
    assert text_section is not None
    relocations = text_section.relocations
    assert len(relocations) == 2

    # 1
    assert relocations[0].address == 0x233
    assert relocations[0].type == 2
    assert relocations[0].size == 32

    assert not relocations[0].is_scattered  # type: ignore[attr-defined]  # type: ignore

    assert relocations[0].has_symbol
    symbol_0 = relocations[0].symbol
    assert symbol_0 is not None
    assert symbol_0.name == "_printf"

    assert relocations[0].has_section
    section_0 = relocations[0].section
    assert section_0 is not None
    assert section_0.name == text_section.name

    # 0
    assert relocations[1].address == 0x21B
    assert relocations[1].type == 1
    assert relocations[1].size == 32

    assert not relocations[1].is_scattered  # type: ignore[attr-defined]  # type: ignore

    assert not relocations[1].has_symbol

    assert relocations[1].has_section
    section_1 = relocations[1].section
    assert section_1 is not None
    assert section_1.name == text_section.name

    # __compact_unwind__LD  Section
    cunwind_section = helloworld.get_section("__compact_unwind")
    assert cunwind_section is not None
    relocations = cunwind_section.relocations
    assert len(relocations) == 1

    # 0
    assert relocations[0].address == 0x247
    assert relocations[0].type == 0
    assert relocations[0].size == 32

    assert not relocations[0].is_scattered  # type: ignore[attr-defined]  # type: ignore
    assert not relocations[0].has_symbol

    assert relocations[0].has_section
    section_cu = relocations[0].section
    assert section_cu is not None
    assert section_cu.name == "__cstring"


def test_data_in_code():
    binary = parse_macho("MachO/MachO32_ARM_binary_data-in-code-LLVM.bin").at(0)
    assert binary is not None

    assert binary.has_data_in_code
    dcode = binary.data_in_code
    assert dcode is not None

    assert dcode.data_offset == 0x11C
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

    # Exercise str() on DataCodeEntry (covers operator<< and to_string)
    entry_str = str(dcode.entries[0])
    assert "DATA" in entry_str
    assert hash(dcode.entries[0]) != 0

    # Exercise str() on DataInCode
    output = str(dcode)
    assert len(output) > 0


def test_segment_split_info():
    binary = parse_macho("MachO/FAT_MachO_x86_x86-64_library_libdyld.dylib").at(1)
    assert binary is not None

    assert binary.has_segment_split_info
    ssi = binary.segment_split_info
    assert ssi is not None
    assert ssi.data_offset == 32852
    assert ssi.data_size == 292
    output = str(ssi)
    assert "offset" in output
    assert hash(ssi) != 0


def test_dyld_environment():
    binary = parse_macho("MachO/MachO64_x86-64_binary_safaridriver.bin").at(0)
    assert binary is not None
    assert binary.has_dyld_environment
    dyld_env = binary.dyld_environment
    assert dyld_env is not None
    assert (
        dyld_env.value
        == "DYLD_VERSIONED_FRAMEWORK_PATH=/System/Library/StagedFrameworks/Safari"
    )
    output = str(dyld_env)
    assert "DYLD_VERSIONED_FRAMEWORK_PATH" in output
    assert hash(dyld_env) != 0


def test_sub_framework():
    binary = parse_macho("MachO/FAT_MachO_x86_x86-64_library_libdyld.dylib").at(0)
    assert binary is not None
    assert binary.has_sub_framework
    sub_framework = binary.sub_framework
    assert sub_framework is not None
    assert sub_framework.umbrella == "System"
    output = str(sub_framework)
    assert "System" in output
    assert hash(sub_framework) != 0
    assert "umbrella" in lief.to_json(sub_framework)


def test_unwind():
    binary = parse_macho("MachO/MachO64_x86-64_binary_sshd.bin").at(0)
    assert binary is not None

    functions = sorted(binary.functions, key=lambda f: f.address)

    assert len(functions) == 2619
    assert binary.is_macos

    assert functions[0].address == 2624
    assert functions[0].size == 0
    assert functions[0].name == ""

    assert functions[-1].address == 0x1000A4F65
    assert functions[-1].size == 0
    assert functions[-1].name == "ctor_0"


def test_build_version():
    binary = parse_macho("MachO/FAT_MachO_arm-arm64-binary-helloworld.bin")
    assert binary is not None
    assert binary[lief.MachO.Header.CPU_TYPE.ARM64] is not None
    assert binary.get(lief.MachO.Header.CPU_TYPE.ARM) is not None
    assert binary[lief.MachO.Header.CPU_TYPE.X86_64] is None

    target = binary[1]
    assert target is not None

    assert target.has_build_version
    assert target.is_ios
    build_version = target.build_version
    assert build_version is not None

    assert build_version.minos == [12, 1, 0]
    assert build_version.sdk == [12, 1, 0]
    assert build_version.platform == lief.MachO.BuildVersion.PLATFORMS.IOS

    tools = build_version.tools
    assert len(tools) == 1
    assert tools[0].version == [409, 12, 0]
    assert tools[0].tool == lief.MachO.BuildToolVersion.TOOLS.LD

    # Exercise str() on BuildVersion (covers the print() method)
    output = str(build_version)
    assert "IOS" in output
    assert "12.1.0" in output

    # Exercise str() on BuildToolVersion
    tool_str = str(tools[0])
    assert len(tool_str) > 0

    # Exercise property setters
    build_version.platform = lief.MachO.BuildVersion.PLATFORMS.MACOS
    assert build_version.platform == lief.MachO.BuildVersion.PLATFORMS.MACOS

    build_version.minos = [13, 0, 0]
    assert build_version.minos == [13, 0, 0]

    build_version.sdk = [13, 1, 0]
    assert build_version.sdk == [13, 1, 0]


def test_segment_index():
    binary = parse_macho("MachO/MachO64_x86-64_binary_safaridriver.bin").at(0)
    assert binary is not None
    linkedit = binary.get_segment("__LINKEDIT")
    assert linkedit is not None
    assert linkedit.index == len(binary.segments) - 1
    data_seg = binary.get_segment("__DATA")
    assert data_seg is not None
    original_data_index = data_seg.index

    # Add a new segment (it should be placed right beore __LINKEDIT)
    segment = lief.MachO.SegmentCommand("__LIEF", [0x60] * 0x100)
    segment = binary.add(segment)  # type: ignore[assignment]
    assert isinstance(segment, lief.MachO.SegmentCommand)
    linkedit2 = binary.get_segment("__LINKEDIT")
    assert linkedit2 is not None
    assert segment.index == linkedit2.index - 1
    assert segment.index == original_data_index + 1

    # discard changes
    binary = parse_macho("MachO/MachO64_x86-64_binary_safaridriver.bin").at(0)
    assert binary is not None
    text_segment = binary.get_segment("__TEXT")
    assert text_segment is not None
    data_seg2 = binary.get_segment("__DATA")
    assert data_seg2 is not None
    original_data_index = data_seg2.index

    binary.remove(text_segment)
    data_seg3 = binary.get_segment("__DATA")
    assert data_seg3 is not None
    assert data_seg3.index == original_data_index - 1
    linkedit3 = binary.get_segment("__LINKEDIT")
    assert linkedit3 is not None
    assert linkedit3.index == original_data_index
    pagezero = binary.get_segment("__PAGEZERO")
    assert pagezero is not None
    assert pagezero.index == 0


def test_offset_to_va():

    # |Name        |Virtual Address|Virtual Size|Offset|Size
    # +------------+---------------+------------+------+----
    # |__PAGEZERO  |0x0            |0x100000000 |0x0   |0x0
    # |__TEXT      |0x100000000    |0x4000      |0x0   |0x4000
    # |__DATA_CONST|0x100004000    |0x4000      |0x4000|0x4000
    # |__DATA      |0x100008000    |0x8000      |0x8000|0x4000
    # |__LINKEDIT  |0x100010000    |0x4000      |0xc000|0x130

    sample = get_sample("MachO/MachO64_x86-64_binary_large-bss.bin")
    fat = lief.MachO.parse(sample)
    assert fat is not None
    large_bss = fat.at(0)
    assert large_bss is not None
    seg0 = large_bss.segment_from_offset(0)
    assert seg0 is not None
    assert seg0.name == "__TEXT"
    seg1 = large_bss.segment_from_offset(0x4001)
    assert seg1 is not None
    assert seg1.name == "__DATA_CONST"
    seg2 = large_bss.segment_from_offset(0xC000)
    assert seg2 is not None
    assert seg2.name == "__LINKEDIT"
    seg3 = large_bss.segment_from_offset(0xC001)
    assert seg3 is not None
    assert seg3.name == "__LINKEDIT"


def test_get_section():
    sample = get_sample("MachO/MachO64_x86-64_binary_large-bss.bin")
    fat = lief.MachO.parse(sample)
    assert fat is not None
    macho = fat.at(0)
    assert macho is not None
    assert macho.get_section("__DATA_CONST", "__got") is not None


def test_segment_add_section():
    binary = parse_macho("MachO/MachO64_x86-64_binary_safaridriver.bin").at(0)
    assert binary is not None

    section = lief.MachO.Section.create("__bar", [1, 2, 3])
    assert section is not None

    existing_segment = binary.get_segment("__TEXT")
    assert existing_segment is not None
    new_segment = lief.MachO.SegmentCommand("__FOO")

    for segment in (existing_segment, new_segment):
        assert not segment.has_section(str(section.name))
        assert not segment.has(section)
        assert segment.numberof_sections == len(segment.sections)

        numberof_sections = segment.numberof_sections

        section = segment.add_section(section)
        assert section is not None
        assert segment.numberof_sections == numberof_sections + 1
        assert segment.has_section(str(section.name))
        assert segment.has(section)
        assert section in segment.sections


def test_issue_728():
    x86_64_binary = parse_macho("MachO/MachO64_x86-64_binary_safaridriver.bin").at(0)
    assert x86_64_binary is not None
    arm64_binary = parse_macho("MachO/FAT_MachO_arm-arm64-binary-helloworld.bin").take(
        lief.MachO.Header.CPU_TYPE.ARM64
    )
    assert arm64_binary is not None

    segment = lief.MachO.SegmentCommand("__FOO")
    new_section = lief.MachO.Section.create("__bar", [1, 2, 3])
    assert new_section is not None
    segment.add_section(new_section)

    for parsed in (x86_64_binary, arm64_binary):
        new_segment = parsed.add(segment)
        assert isinstance(new_segment, lief.MachO.SegmentCommand)
        assert new_segment.virtual_size == parsed.page_size


def test_twolevel_hints():
    sample = parse_macho("MachO/ios1-expr.bin")[0]
    assert sample is not None
    tw_hints = cast(
        lief.MachO.TwoLevelHints, sample[lief.MachO.LoadCommand.TYPE.TWOLEVEL_HINTS]
    )
    assert tw_hints is not None
    lief.logging.info(tw_hints)
    hints = tw_hints.hints
    assert len(hints) == 26
    lief.logging.info(hints[0])
    assert sum(hints) == 10854400
    assert hints[0] == 54528
    assert (
        hashlib.sha256(tw_hints.data).hexdigest()
        == "e44cef3a83eb89954557a9ad2a36ebf4794ce0385da5a39381fdadc3e6037beb"
    )
    assert tw_hints.command_offset == 1552
    lief.logging.info(lief.to_json(tw_hints))


def test_overlay():
    sample = parse_macho("MachO/overlay_data.bin").at(0)
    assert sample is not None
    assert bytes(sample.overlay) == b"\x00overlay data"


def test_issue_1055():
    sample = parse_macho("MachO/issue_1055.bin").at(0)
    assert sample is not None
    for section in sample.sections:
        size = len(section.content)
        assert size is not None


def test_unknown_command():
    sample = parse_macho("MachO/libadd_unknown_cmd.so").at(0)
    assert sample is not None
    unknown_cmd = sample.commands[15]
    assert isinstance(unknown_cmd, lief.MachO.UnknownCommand)
    assert unknown_cmd.original_command == 0x3333
    lief.logging.info(hash(unknown_cmd))
    lief.logging.info(unknown_cmd)


def test_subclients():
    macho = parse_macho("MachO/StocksAnalytics").at(0)
    assert macho is not None
    assert len(macho.subclients) == 19

    assert macho.subclients[0].client == "NewsArticles"
    assert macho.subclients[-1].client == "StocksAppKitBundle"
    output = str(macho.subclients[0])
    assert "NewsArticles" in output
    assert hash(macho.subclients[0]) != 0


def test_bindings_iterator():
    dyld = parse_macho("MachO/MachO64_x86-64_binary_sshd.bin").at(0)
    assert dyld is not None
    chained = parse_macho("MachO/PlugInKitDaemon").at(0)
    assert chained is not None
    shared_cache = parse_macho("MachO/liblog_srp.dylib").at(0)
    assert shared_cache is not None

    dyld_bindings = list(dyld.bindings)
    chained_bindings = list(chained.bindings)
    indirect_bindings = list(shared_cache.bindings)

    assert len(dyld_bindings) == 323
    assert len(chained_bindings) == 546
    assert len(indirect_bindings) == 25

    sym1 = dyld_bindings[320].symbol
    assert sym1 is not None
    assert sym1.name == "_vfprintf"
    sym2 = chained_bindings[540].symbol
    assert sym2 is not None
    assert sym2.name == "__objc_empty_cache"

    sym3 = indirect_bindings[0].symbol
    assert sym3 is not None
    assert sym3.name == "___memcpy_chk"
    sym4 = indirect_bindings[-1].symbol
    assert sym4 is not None
    assert sym4.name == "_strcmp"


def test_va_range():
    macho = parse_macho("MachO/macho-arm64-osx-chained-fixups.bin").at(0)
    assert macho is not None
    va_ranges = macho.va_ranges
    assert va_ranges.start == 0x100000000
    assert va_ranges.end == 0x100010000


@pytest.mark.private
def test_routine():
    macho = parse_macho("private/MachO/CoreFoundation").at(0)
    assert macho is not None
    routine = macho.routine_command
    assert routine is not None
    assert routine.init_address == 0x00000001803F0AA4
    assert routine.init_module == 0
    assert routine.reserved1 == 0
    assert routine.reserved2 == 0
    assert routine.reserved3 == 0
    assert routine.reserved4 == 0
    assert routine.reserved5 == 0
    assert routine.reserved6 == 0
    output = str(routine)
    assert "init_address" in output
    assert hash(routine) != 0


@pytest.mark.private
def test_arm64e():
    sample = parse_macho("private/MachO/libCoreKE_arm64e.dylib").at(0)
    assert sample is not None
    assert sample.support_arm64_ptr_auth


def test_find_library():
    macho = parse_macho("MachO/lief-dwarf-plugin-darwin-arm64.dylib").at(0)
    assert macho is not None
    assert macho.find_library("/foo/lief-dwarf-plugin-darwin-arm64.dylib") is None
    assert macho.find_library("lief-dwarf-plugin-darwin-arm64.dylib") is not None
    assert macho.find_library("@rpath/lief-dwarf-plugin-darwin-arm64.dylib") is not None
    assert macho.find_library("/usr/lib/libSystem.B.dylib") is not None


def test_resolve_function():
    macho = parse_macho("MachO/lief-dwarf-plugin-darwin-arm64.dylib").at(0)
    assert macho is not None
    assert macho.get_function_address("CorePluginABIVersion") == 0x1CF0

    macho = parse_macho("MachO/RNCryptor.bin").at(0)
    assert macho is not None
    assert macho.get_function_address("_RNCryptorVersionString") == 0x00012988


def test_virtual_address_to_offset_bss():
    # c.f. https://github.com/lief-project/LIEF/issues/1299
    macho = parse_macho("MachO/do_add.bin").at(0)
    assert macho is not None

    data_segment = macho.get_segment("__DATA")
    assert data_segment is not None
    assert data_segment.virtual_address == 0x100008000
    # Contains only `__bss` section (S_ZEROFILL); thus no backing storage
    assert data_segment.file_size == 0

    offset = macho.virtual_address_to_offset(data_segment.virtual_address)
    assert offset is lief.lief_errors.conversion_error


def test_encryption_info_str():
    macho = parse_macho("MachO/RNCryptor.bin").at(0)
    assert macho is not None
    enc_info = macho.encryption_info
    assert enc_info is not None
    output = str(enc_info)
    assert "crypt" in output
    assert hash(enc_info) != 0


def test_dyld_exports_trie_str():
    fat = parse_macho(
        "MachO/9edfb04c55289c6c682a25211a4b30b927a86fe50b014610d04d6055bd4ac23d_crypt_and_hash.macho"
    )
    target = fat.take(lief.MachO.Header.CPU_TYPE.ARM64)
    assert target is not None
    exports = cast(
        lief.MachO.DyldExportsTrie,
        target.get(lief.MachO.LoadCommand.TYPE.DYLD_EXPORTS_TRIE),
    )
    assert exports is not None
    output = str(exports)
    assert "offset" in output

    trie_output = exports.show_export_trie()
    assert len(trie_output) > 0
    assert hash(exports) != 0


def test_header_flags():
    macho = parse_macho("MachO/MachO64_x86-64_binary_all.bin").at(0)
    assert macho is not None
    header = macho.header
    assert header is not None

    output = str(header)
    assert "Magic" in output

    flags_list = header.flags_list
    assert len(flags_list) > 0

    header.add(lief.MachO.Header.FLAGS.ROOT_SAFE)
    assert header.has(lief.MachO.Header.FLAGS.ROOT_SAFE)

    header.remove(lief.MachO.Header.FLAGS.ROOT_SAFE)
    assert not header.has(lief.MachO.Header.FLAGS.ROOT_SAFE)
    assert hash(header) != 0


def test_dylinker_str():
    macho = parse_macho("MachO/MachO64_x86-64_binary_all.bin").at(0)
    assert macho is not None
    dylinker = macho.dylinker
    assert dylinker is not None
    output = str(dylinker)
    assert "dyld" in output


def test_dynamic_symbol_command_str():
    macho = parse_macho("MachO/MachO64_x86-64_binary_all.bin").at(0)
    assert macho is not None
    dyscmd = macho.dynamic_symbol_command
    assert dyscmd is not None
    output = str(dyscmd)
    assert "local" in output.lower()


def test_main_command_str():
    macho = parse_macho("MachO/MachO64_x86-64_binary_all.bin").at(0)
    assert macho is not None
    main_cmd = macho.main_command
    assert main_cmd is not None
    output = str(main_cmd)
    assert "entrypoint" in output


def test_dylib_command_str():
    macho = parse_macho("MachO/MachO64_x86-64_binary_all.bin").at(0)
    assert macho is not None
    libs = macho.libraries
    assert len(libs) > 0
    output = str(libs[0])
    assert "name=" in output


def test_note_command_str(tmp_path: Path):
    src = get_sample("MachO/MachO64_x86-64_binary_all.bin")
    with open(src, "rb") as f:
        data = bytearray(f.read())

    # Inject an LC_NOTE command into the binary
    HEADER_SIZE = 32
    ncmds = struct.unpack_from("<I", data, 16)[0]
    sizeofcmds = struct.unpack_from("<I", data, 20)[0]

    LC_NOTE = 0x31
    note_cmdsize = 40
    note_owner = b"TestNote\x00\x00\x00\x00\x00\x00\x00\x00"
    note_cmd = struct.pack("<II16sQQ", LC_NOTE, note_cmdsize, note_owner, 0, 0)

    insert_pos = HEADER_SIZE + sizeofcmds
    data[insert_pos:insert_pos] = note_cmd
    struct.pack_into("<I", data, 16, ncmds + 1)
    struct.pack_into("<I", data, 20, sizeofcmds + note_cmdsize)

    patched = tmp_path / "with_note.bin"
    patched.write_bytes(data)

    fat = lief.MachO.parse(patched)
    assert fat is not None
    macho = fat.at(0)
    assert macho is not None
    note = macho[lief.MachO.LoadCommand.TYPE.NOTE]
    assert note is not None
    output = str(note)
    assert len(output) > 0


def test_load_command_str():
    macho = parse_macho("MachO/MachO64_x86-64_binary_all.bin").at(0)
    assert macho is not None
    for cmd in macho.commands:
        output = str(cmd)
        assert len(output) > 0
