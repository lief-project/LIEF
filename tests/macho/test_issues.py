import subprocess
import sys
from pathlib import Path
from textwrap import dedent

import lief
import pytest
from utils import address_space_limiter, get_sample, parse_macho


def test_945():
    target = parse_macho("MachO/python3_issue_476.bin").at(0)
    assert target is not None
    segments = target.segments

    assert all(isinstance(s, lief.MachO.SegmentCommand) for s in segments)
    assert "__LINKEDIT" in {s.name for s in segments}

    for load_command in target.commands:
        if load_command.command in (
            lief.MachO.LoadCommand.TYPE.SEGMENT,
            lief.MachO.LoadCommand.TYPE.SEGMENT_64,
        ):
            assert isinstance(load_command, lief.MachO.SegmentCommand)


def test_993(tmp_path: Path):
    target = parse_macho("MachO/alivcffmpeg_armv7.dylib")
    out = Path(tmp_path) / "issue_993.dylib"
    target.write(out)

    new = lief.MachO.parse(out)
    assert new is not None
    not_err, msg = lief.MachO.check_layout(new)
    assert not_err, msg


def test_1087():
    target = parse_macho("MachO/fbcb7580db7bc04d695c3fd0308bb344_issue_1087").at(0)
    assert target is not None
    assert target.offset_to_virtual_address(0x42DAE) == 0x100042DAE


def test_endianness():
    target = parse_macho("MachO/macho-issue-1110.bin").at(0)
    assert target is not None

    assert len(target.segments) == 3


def test_1130(tmp_path: Path):
    target = parse_macho("MachO/issue_1130.macho").at(0)
    assert target is not None
    target.shift(0x4000)

    output = tmp_path / "new.macho"
    target.write(output)

    fat = lief.MachO.parse(output)
    assert fat is not None
    new = fat.at(0)
    assert new is not None
    assert lief.MachO.check_layout(new)[0]

    data_seg = new.get_segment("__DATA")
    assert data_seg is not None
    assert data_seg.virtual_address == 0x100008000


def test_1132():
    # Check if cache is updated that is used by segment_from_offset
    binary = parse_macho("MachO/FAT_MachO_arm-arm64-binary-helloworld.bin").take(
        lief.MachO.Header.CPU_TYPE.ARM64
    )
    assert binary is not None

    text_segment = binary.get_segment("__TEXT")
    assert text_segment is not None
    binary.extend_segment(text_segment, 0x10000)

    def can_cache_segment(seg):
        return seg.file_offset > 0 or seg.file_size > 0 or seg.name == "__TEXT"

    for seg in binary.segments:
        if can_cache_segment(seg):
            assert binary.segment_from_offset(seg.file_offset) == seg


@pytest.mark.private
def test_issue_ntype(tmp_path: Path):
    macho = parse_macho("private/MachO/amfid.arm64e").at(0)
    assert macho is not None
    output = tmp_path / "amfid_out.arm64e"

    assert macho.symbols[0].raw_type == 60

    macho.write(output)
    fat = lief.MachO.parse(output)
    assert fat is not None
    new = fat.at(0)
    assert new is not None
    assert new.symbols[0].raw_type == 60


def test_huge_recursion():
    """Bug found with Codex 5.3"""
    macho = lief.MachO.parse(get_sample("MachO/deep_exports.bin"))
    assert macho is not None


def test_zero_div():
    """Bug found with Codex 5.3"""
    macho = lief.MachO.parse(get_sample("MachO/stub_div0.bin"))
    assert macho is not None


def test_1344(tmp_path: Path):
    sample = (
        "MachO/"
        "42d4f6b799d5d3ff88c50d4c6966773d269d19793226724b5e893212091bf737"
        "_dyld.macho"
    )
    target = parse_macho(sample).at(0)
    assert target is not None

    thread = target.thread_command
    assert thread is not None

    commands = target.commands

    out = tmp_path / "issue_1344.macho"
    target.write(out)

    fat = lief.MachO.parse(out)
    assert fat is not None
    new = fat.at(0)
    assert new is not None
    assert [c.command for c in new.commands] == [c.command for c in commands]

    header_size = 28  # sizeof(Header)
    off = header_size
    for cmd in new.commands:
        off += cmd.size
    assert off == new.header.sizeof_cmds + header_size


@pytest.mark.private
def test_large_dyld_rebase_count():
    target = parse_macho("private/MachO/issue_rebase_count.macho").at(0)
    assert target is not None

    dyld_info = target.dyld_info
    assert dyld_info is not None

    relocations = list(target.relocations)
    assert len(relocations) < 0x1000

    # The display walker must stay bounded as well (no multi-GB string).
    opcodes_repr = dyld_info.show_rebases_opcodes
    assert opcodes_repr.count("rebase(") < 0x1000


@pytest.mark.private
def test_negative_relative_offset():
    sample = Path(get_sample("private/MachO/negative_relative_offset.macho")).absolute()

    subprocess.check_call(
        [
            sys.executable,
            "-c",
            dedent("""\
            import lief
            import sys
            fat = lief.MachO.parse(sys.argv[1])
            b = fat.at(0)
            assert b is not None
            [bytes(s.content) for s in b.sections]"""),
            str(sample),
        ],
        timeout=30.0,
    )

    fat = lief.MachO.parse(sample)
    assert fat is not None
    target = fat.at(0)
    assert target is not None
    assert len(target.sections) == 1
    assert bytes(target.sections[0].content) == b""


@pytest.mark.private
def test_dyld_corrupted_indices():
    sample = get_sample("private/MachO/dyld_bad_indices.macho")
    subprocess.check_call(
        [
            sys.executable,
            "-c",
            dedent(f"""\
            import lief
            fat = lief.MachO.parse(r"{sample}")
            di = fat.at(0).dyld_info
            assert di is not None
            di.show_rebases_opcodes
            di.show_bind_opcodes
            di.show_lazy_bind_opcodes
            di.show_weak_bind_opcodes"""),
        ],
        timeout=30.0,
    )

    target = parse_macho(sample).at(0)
    assert target is not None
    di = target.dyld_info
    assert di is not None

    assert "<invalid>" in di.show_rebases_opcodes
    assert "<invalid>" in di.show_bind_opcodes


@pytest.mark.private
def test_symtab_uncapped_alloc():
    sample = get_sample("private/MachO/symtab_uncapped_alloc.macho")
    subprocess.check_call(
        [
            sys.executable,
            "-c",
            dedent(f"""\
            import lief
            fat = lief.MachO.parse(r"{sample}")
            assert fat is not None
            b = fat.at(0)
            assert b is not None
            assert [s.name for s in b.segments] == ["__TEXT"]
            assert len(b.symbols) == 0"""),
        ],
        timeout=30.0,
        preexec_fn=address_space_limiter(),
    )

    target = parse_macho(sample).at(0)
    assert target is not None
    assert [s.name for s in target.segments] == ["__TEXT"]
    assert len(target.symbols) == 0


@pytest.mark.private
def test_build_version_ntools():
    sample = get_sample("private/MachO/ntools.macho")
    subprocess.check_call(
        [
            sys.executable,
            "-c",
            dedent(f"""\
            import lief
            fat = lief.MachO.parse(r"{sample}")
            assert fat is not None
            b = fat.at(0)
            assert b is not None
            tools = sum(len(c.tools) for c in b.commands
                        if isinstance(c, lief.MachO.BuildVersion))
            assert tools == 0, tools"""),
        ],
        timeout=30.0,
        preexec_fn=address_space_limiter(),
    )


@pytest.mark.private
def test_twolevel_hints():
    sample = get_sample("private/MachO/nhints.macho")
    subprocess.check_call(
        [
            sys.executable,
            "-c",
            dedent(f"""\
            import lief
            fat = lief.MachO.parse(r"{sample}")
            assert fat is not None
            b = fat.at(0)
            assert b is not None
            hints = sum(len(list(c.hints)) for c in b.commands
                        if isinstance(c, lief.MachO.TwoLevelHints))
            # bounded by file_size / sizeof(twolevel_hint)
            import os
            assert hints <= os.path.getsize(r"{sample}") // 4, hints"""),
        ],
        timeout=30.0,
        preexec_fn=address_space_limiter(),
    )


@pytest.mark.private
def test_function_variants_overflow():
    sample = get_sample("private/MachO/func_variants.macho")
    subprocess.check_call(
        [
            sys.executable,
            "-c",
            dedent(f"""\
            import lief
            fat = lief.MachO.parse(r"{sample}")
            assert fat is not None
            b = fat.at(0)
            assert b is not None
            fv = b.function_variants
            assert fv is not None
            entries = sum(len(list(t.entries)) for t in fv.runtime_table)
            assert entries <= 0x10000, entries"""),
        ],
        timeout=30.0,
        preexec_fn=address_space_limiter(),
    )


@pytest.mark.private
def test_nsects_bound_checks():
    sample = get_sample("private/MachO/nsects_quadratic.macho")
    subprocess.check_call(
        [
            sys.executable,
            "-c",
            dedent(f"""\
            import lief
            fat = lief.MachO.parse(r"{sample}")
            assert fat is not None
            b = fat.at(0)
            assert b is not None
            # cmdsize leaves no room for sections -> none are parsed.
            assert len(b.sections) < 0x1000, len(b.sections)"""),
        ],
        timeout=30.0,
        preexec_fn=address_space_limiter(),
    )

    target = parse_macho(sample).at(0)
    assert target is not None
    assert len(target.sections) < 0x1000


@pytest.mark.private
def test_rebase_uleb_times_uncapped():
    sample = get_sample("private/MachO/rebase_uleb_times.macho")
    subprocess.check_call(
        [
            sys.executable,
            "-c",
            dedent(f"""\
            import lief
            fat = lief.MachO.parse(r"{sample}")
            assert fat is not None
            b = fat.at(0)
            assert b is not None
            assert len(list(b.relocations)) < 0x1000, len(list(b.relocations))"""),
        ],
        timeout=30.0,
        preexec_fn=address_space_limiter(),
    )

    target = parse_macho(sample).at(0)
    assert target is not None
    assert len(list(target.relocations)) < 0x1000


@pytest.mark.private
def test_zero_cmdsize():
    sample = get_sample("private/MachO/zero_cmdsize.macho")
    subprocess.check_call(
        [
            sys.executable,
            "-c",
            dedent(f"""\
            import lief
            fat = lief.MachO.parse(r"{sample}")
            assert fat is not None
            b = fat.at(0)
            assert b is not None
            assert [s.name for s in b.segments] == ["__TEXT"]
            assert len(b.commands) == 1"""),
        ],
        timeout=30.0,
        preexec_fn=address_space_limiter(),
    )

    target = parse_macho(sample).at(0)
    assert target is not None

    assert [s.name for s in target.segments] == ["__TEXT"]
    assert len(target.commands) == 1


@pytest.mark.private
def test_dyld_chained_fixups_underflow():
    sample = get_sample("private/MachO/chained_underflow.macho")
    subprocess.check_call(
        [
            sys.executable,
            "-c",
            dedent(f"""\
            import lief
            cfg = lief.MachO.ParserConfig()
            cfg.from_dyld_shared_cache = True
            fat = lief.MachO.parse(r"{sample}", cfg)
            assert fat is not None
            b = fat.at(0)
            assert b is not None
            [s.name for s in b.segments]"""),
        ],
        timeout=30.0,
    )

    cfg = lief.MachO.ParserConfig()
    cfg.from_dyld_shared_cache = True
    fat = lief.MachO.parse(sample, cfg)
    assert fat is not None
    target = fat.at(0)
    assert target is not None
    assert {s.name for s in target.segments} == {"__TEXT", "__LINKEDIT"}


def test_va_out_of_segment():
    fat = parse_macho(
        "MachO/42d4f6b799d5d3ff88c50d4c6966773d269d19793226724b5e893212091bf737_dyld.macho"
    )
    macho = fat.at(0)
    assert macho is not None

    segment = next(s for s in macho.segments if s.virtual_size > len(s.content) > 0)

    address = segment.virtual_address + len(segment.content) + 0x100
    assert len(macho.get_content_from_virtual_address(address, 16)) == 0

    # a valid address still returns data, truncated to what is available
    valid = segment.virtual_address + len(segment.content) - 4
    assert len(macho.get_content_from_virtual_address(valid, 16)) == 4
