from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from typing import cast

import lief
import pytest
from utils import check_layout, parse_elf

CONFIG = lief.ELF.Builder.config_t()
CONFIG.notes = True


def test_change_note(tmp_path: Path):
    etterlog = parse_elf("ELF/ELF64_x86-64_binary_etterlog.bin")
    build_id = etterlog[lief.ELF.Note.TYPE.GNU_BUILD_ID]
    assert build_id is not None

    new_desc = [i & 0xFF for i in range(500)]
    build_id.description = new_desc
    output = tmp_path / "etterlog"
    etterlog.write(output, CONFIG)

    etterlog_updated = lief.ELF.parse(output)
    assert etterlog_updated is not None

    assert (
        etterlog[lief.ELF.Note.TYPE.GNU_BUILD_ID]
        == etterlog_updated[lief.ELF.Note.TYPE.GNU_BUILD_ID]
    )


def test_remove_note(tmp_path: Path):
    etterlog = parse_elf("ELF/ELF64_x86-64_binary_etterlog.bin")
    assert etterlog is not None
    output = tmp_path / "etterlog"
    lief.logging.info(output)

    build_id = etterlog[lief.ELF.Note.TYPE.GNU_BUILD_ID]
    assert build_id is not None
    etterlog -= build_id
    assert etterlog is not None

    etterlog.write(output, CONFIG)
    etterlog_updated = lief.ELF.parse(output)
    assert etterlog_updated is not None
    check_layout(etterlog_updated)
    assert not etterlog_updated.has(lief.ELF.Note.TYPE.GNU_BUILD_ID)


def test_add_note(tmp_path: Path):
    etterlog = parse_elf("ELF/ELF64_x86-64_binary_etterlog.bin")
    output = tmp_path / "etterlog"
    note = lief.ELF.Note.create(
        "Foo", lief.ELF.Note.TYPE.GNU_GOLD_VERSION, [1, 2], section_name=""
    )
    assert note is not None
    etterlog += note
    assert etterlog is not None

    etterlog.write(output, CONFIG)

    etterlog_updated = lief.ELF.parse(output)
    assert etterlog_updated is not None
    check_layout(etterlog_updated)
    assert etterlog_updated.has(lief.ELF.Note.TYPE.GNU_GOLD_VERSION)

    # The string printed is largely irrelevant, but running print ensures no
    # regression occurs in a previous Note::dump segfault
    # https://github.com/lief-project/LIEF/issues/300
    with StringIO() as temp_stdout:
        with redirect_stdout(temp_stdout):
            lief.logging.info(etterlog)


def test_android_note(tmp_path: Path):
    ndkr16 = parse_elf("ELF/ELF64_AArch64_piebinary_ndkr16.bin")
    output = tmp_path / "etterlog"

    note = cast(lief.ELF.AndroidIdent, ndkr16.get(lief.ELF.Note.TYPE.ANDROID_IDENT))
    assert note.sdk_version == 21
    assert note.ndk_version[:4] == "r16b"
    assert note.ndk_build_number[:7] == "4479499"

    note.sdk_version = 15
    note.ndk_version = "r15c"
    note.ndk_build_number = "123456"

    note = cast(lief.ELF.AndroidIdent, ndkr16.get(lief.ELF.Note.TYPE.ANDROID_IDENT))

    assert note.sdk_version == 15
    assert note.ndk_version[:4] == "r15c"
    assert note.ndk_build_number[:6] == "123456"

    ndkr16.write(output, CONFIG)

    ndkr15 = lief.ELF.parse(output)
    assert ndkr15 is not None

    check_layout(ndkr15)

    note = cast(lief.ELF.AndroidIdent, ndkr15.get(lief.ELF.Note.TYPE.ANDROID_IDENT))

    assert note.sdk_version == 15
    assert note.ndk_version[:4] == "r15c"
    assert note.ndk_build_number[:6] == "123456"


def test_issue_816(tmp_path: Path):
    elf = parse_elf("ELF/elf_notes_issue_816.bin")
    output = tmp_path / "elf_notes_issue_816"

    assert len(elf.notes) == 40

    elf.write(output, CONFIG)
    new = lief.ELF.parse(output)
    assert new is not None
    check_layout(new)
    assert len(new.notes) == 40


def test_crashpad():
    RAW_CRASHPAD = "0900000008000000494e464f437261736870616400000000d85cf00300000000"
    note = lief.ELF.Note.create(bytes.fromhex(RAW_CRASHPAD))
    assert note is not None
    assert note.type == lief.ELF.Note.TYPE.CRASHPAD
    assert note.name == "Crashpad"


def test_note_aarch64_features():
    GNU_PROPERTY_AARCH64_FEATURE_1_AND = (
        "040000001000000005000000474e5500000000c0040000000100000000000000"
    )

    note = lief.ELF.Note.create(
        raw=bytes.fromhex(GNU_PROPERTY_AARCH64_FEATURE_1_AND),
        file_type=lief.ELF.Header.FILE_TYPE.NONE,
        arch=lief.ELF.ARCH.AARCH64,
        cls=lief.ELF.Header.CLASS.ELF64,
    )
    assert isinstance(note, lief.ELF.NoteGnuProperty)
    assert len(note.properties) == 1
    assert (
        note.find(lief.ELF.NoteGnuProperty.Property.TYPE.AARCH64_FEATURES) is not None
    )
    assert note.find(lief.ELF.NoteGnuProperty.Property.TYPE.GENERIC) is None

    assert isinstance(note.properties[0], lief.ELF.AArch64Feature)
    assert note.properties[0].features == [lief.ELF.AArch64Feature.FEATURE.BTI]
    assert (
        note.properties[0].type
        == lief.ELF.NoteGnuProperty.Property.TYPE.AARCH64_FEATURES
    )
    assert str(note.properties[0])
    lief.logging.info(note.properties[0])
    lief.logging.info(note)


def test_note_aarch_pauth():
    GNU_PROPERTY_AARCH64_FEATURE_PAUTH = "040000001800000005000000474e5500010000c0100000002a000000000000000100000000000000"

    note = lief.ELF.Note.create(
        raw=bytes.fromhex(GNU_PROPERTY_AARCH64_FEATURE_PAUTH),
        file_type=lief.ELF.Header.FILE_TYPE.NONE,
        arch=lief.ELF.ARCH.AARCH64,
        cls=lief.ELF.Header.CLASS.ELF64,
    )
    assert isinstance(note, lief.ELF.NoteGnuProperty)
    assert len(note.properties) == 1
    assert note.find(lief.ELF.NoteGnuProperty.Property.TYPE.AARCH64_PAUTH) is not None
    assert note.find(lief.ELF.NoteGnuProperty.Property.TYPE.GENERIC) is None

    assert isinstance(note.properties[0], lief.ELF.AArch64PAuth)
    assert note.properties[0].platform == 42
    assert note.properties[0].version == 1
    assert str(note.properties[0])

    lief.logging.info(note.properties[0])
    lief.logging.info(note)


def test_note_x86_isa():
    GNU_PROPERTY_X86_ISA_1_NEEDED = "040000001800000005000000474e5500028000c00400000001000000020001c00400000000000000"
    note = lief.ELF.Note.create(
        raw=bytes.fromhex(GNU_PROPERTY_X86_ISA_1_NEEDED),
        file_type=lief.ELF.Header.FILE_TYPE.NONE,
        arch=lief.ELF.ARCH.X86_64,
        cls=lief.ELF.Header.CLASS.ELF64,
    )
    assert isinstance(note, lief.ELF.NoteGnuProperty)

    assert len(note.properties) == 2
    assert isinstance(note.properties[0], lief.ELF.X86ISA)
    assert note.properties[0].values == [
        (lief.ELF.X86ISA.FLAG.NEEDED, lief.ELF.X86ISA.ISA.BASELINE)
    ]
    assert note.properties[0].type == lief.ELF.NoteGnuProperty.Property.TYPE.X86_ISA
    assert str(note.properties[0])
    lief.logging.info(note)

    GNU_PROPERTY_X86_ISA_1_NEEDED = "040000001800000005000000474e5500020001c0040000000a000000028000c00400000003000000040000001800000005000000474e5500020001c004000000a0000000028000c00400000030000000"
    note = lief.ELF.Note.create(
        raw=bytes.fromhex(GNU_PROPERTY_X86_ISA_1_NEEDED),
        file_type=lief.ELF.Header.FILE_TYPE.NONE,
        arch=lief.ELF.ARCH.X86_64,
        cls=lief.ELF.Header.CLASS.ELF64,
    )
    assert isinstance(note, lief.ELF.NoteGnuProperty)

    assert len(note.properties) == 1
    assert isinstance(note.properties[0], lief.ELF.X86ISA)
    assert note.properties[0].values == [
        (lief.ELF.X86ISA.FLAG.USED, lief.ELF.X86ISA.ISA.V2),
        (lief.ELF.X86ISA.FLAG.USED, lief.ELF.X86ISA.ISA.V4),
    ]
    assert note.properties[0].type == lief.ELF.NoteGnuProperty.Property.TYPE.X86_ISA
    assert str(note.properties[0])
    lief.logging.info(note)

    GNU_PROPERTY_X86_ISA_1_NEEDED = "040000001800000005000000474e5500000001c0040000000a000000008000c00400000003000000040000001800000005000000474e5500000001c004000000a0000000008000c00400000030000000"
    note = lief.ELF.Note.create(
        raw=bytes.fromhex(GNU_PROPERTY_X86_ISA_1_NEEDED),
        file_type=lief.ELF.Header.FILE_TYPE.NONE,
        arch=lief.ELF.ARCH.X86_64,
        cls=lief.ELF.Header.CLASS.ELF64,
    )
    assert isinstance(note, lief.ELF.NoteGnuProperty)

    assert len(note.properties) == 1
    assert isinstance(note.properties[0], lief.ELF.X86ISA)
    assert note.properties[0].values == [
        (lief.ELF.X86ISA.FLAG.USED, lief.ELF.X86ISA.ISA.SSE),
        (lief.ELF.X86ISA.FLAG.USED, lief.ELF.X86ISA.ISA.SSE3),
    ]
    assert str(note.properties[0])
    lief.logging.info(note)


def test_note_properties():
    GNU_PROPERTY_C = "040000004800000005000000474e5500010000000800000000111100000000000200000000000000020001c0040000001110000000000000028000c0040000001110000000000000020000c0040000000100000000000000"
    note = lief.ELF.Note.create(
        raw=bytes.fromhex(GNU_PROPERTY_C),
        file_type=lief.ELF.Header.FILE_TYPE.NONE,
        arch=lief.ELF.ARCH.X86_64,
        cls=lief.ELF.Header.CLASS.ELF64,
    )
    assert isinstance(note, lief.ELF.NoteGnuProperty)

    assert len(note.properties) == 5
    assert str(note)

    assert isinstance(note.properties[0], lief.ELF.StackSize)
    assert note.properties[0].stack_size == 0x111100

    assert isinstance(note.properties[1], lief.ELF.NoteNoCopyOnProtected)
    assert isinstance(note.properties[2], lief.ELF.X86ISA)
    assert note.properties[2].values == [
        (lief.ELF.X86ISA.FLAG.USED, lief.ELF.X86ISA.ISA.BASELINE),
        (lief.ELF.X86ISA.FLAG.USED, lief.ELF.X86ISA.ISA.UNKNOWN),
        (lief.ELF.X86ISA.FLAG.USED, lief.ELF.X86ISA.ISA.UNKNOWN),
    ]

    assert isinstance(note.properties[4], lief.ELF.X86Features)
    assert note.properties[4].features == [
        (lief.ELF.X86Features.FLAG.NONE, lief.ELF.X86Features.FEATURE.IBT),
    ]


def test_note_needed():
    # GNU_PROPERTY_1_NEEDED with INDIRECT_EXTERN_ACCESS (bit 0 set)
    GNU_PROPERTY_1_NEEDED = (
        "040000001000000005000000474e5500008000b0040000000100000000000000"
    )

    note = lief.ELF.Note.create(
        raw=bytes.fromhex(GNU_PROPERTY_1_NEEDED),
        file_type=lief.ELF.Header.FILE_TYPE.NONE,
        arch=lief.ELF.ARCH.X86_64,
        cls=lief.ELF.Header.CLASS.ELF64,
    )
    assert isinstance(note, lief.ELF.NoteGnuProperty)
    assert len(note.properties) == 1
    assert note.find(lief.ELF.NoteGnuProperty.Property.TYPE.NEEDED) is not None

    prop = note.properties[0]
    assert isinstance(prop, lief.ELF.Needed)
    assert prop.type == lief.ELF.NoteGnuProperty.Property.TYPE.NEEDED
    assert prop.needs == [lief.ELF.Needed.NEED.INDIRECT_EXTERN_ACCESS]
    assert str(prop)
    lief.logging.info(prop)
    lief.logging.info(note)


@pytest.mark.private
def test_qnx_note():
    qnx = parse_elf("private/ELF/qnx_aarch64le_bsdtar")
    stack_info = qnx.get(lief.ELF.Note.TYPE.QNX_STACK)
    assert isinstance(stack_info, lief.ELF.QNXStack)
    lief.logging.info(stack_info)
    assert stack_info.stack_size == 0
    assert stack_info.stack_allocated == 0x1000
    assert not stack_info.is_executable


def test_create_custom_note(tmp_path: Path):
    elf = parse_elf("ELF/ELF64_x86-64_binary_hello-gdb.bin")

    elf += cast(
        lief.ELF.Note,
        lief.ELF.Note.create(
            name="lief-testing",
            original_type=lief.ELF.Note.TYPE.UNKNOWN.value,
            description=list(b"some descriptions"),
            section_name=".lief.note.1",
        ),
    )

    elf += lief.ELF.Note.create(  # type: ignore
        name="lief-testing-alt",
        original_type=lief.ELF.Note.TYPE.UNKNOWN.value,
        description=list(
            b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed"
        ),
        section_name=".lief.note.alternative",
    )

    out = tmp_path / "note-1.elf"

    elf.write(out, CONFIG)

    new = lief.ELF.parse(out)
    assert new is not None
    assert new.get_section(".lief.note.1") is not None
    assert new.get_section(".lief.note.alternative") is not None

    notes = new.notes
    assert len(notes) == 4
    assert notes[2].name == "lief-testing\x00"
    assert bytes(notes[2].description) == b"some descriptions\x00\x00\x00"
    assert notes[3].name == "lief-testing-alt\x00"
    assert (
        bytes(notes[3].description)
        == b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed"
    )
