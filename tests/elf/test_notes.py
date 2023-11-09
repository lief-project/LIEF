#!/usr/bin/env python
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

import lief
from utils import get_sample

lief.logging.set_level(lief.logging.LOGGING_LEVEL.INFO)

config = lief.ELF.Builder.config_t()
config.notes = True;

def test_change_note(tmp_path: Path):
    etterlog = lief.parse(get_sample('ELF/ELF64_x86-64_binary_etterlog.bin'))
    build_id = etterlog[lief.ELF.Note.TYPE.GNU_BUILD_ID]

    new_desc = [i & 0xFF for i in range(500)]
    build_id.description = new_desc
    output = tmp_path / "etterlog"
    etterlog.write(output.as_posix(), config)

    etterlog_updated = lief.parse(output.as_posix())

    assert etterlog[lief.ELF.Note.TYPE.GNU_BUILD_ID] == etterlog_updated[lief.ELF.Note.TYPE.GNU_BUILD_ID]

def test_remove_note(tmp_path: Path):
    etterlog = lief.parse(get_sample('ELF/ELF64_x86-64_binary_etterlog.bin'))
    output = tmp_path / "etterlog"
    print(output)

    build_id = etterlog[lief.ELF.Note.TYPE.GNU_BUILD_ID]
    assert build_id is not None
    etterlog -= build_id

    etterlog.write(output.as_posix(), config)
    etterlog_updated = lief.parse(output.as_posix())
    assert lief.ELF.Note.TYPE.GNU_BUILD_ID not in etterlog_updated

def test_add_note(tmp_path: Path):
    etterlog = lief.parse(get_sample('ELF/ELF64_x86-64_binary_etterlog.bin'))
    output = tmp_path / "etterlog"
    note = lief.ELF.Note.create("Foo", lief.ELF.Note.TYPE.GNU_GOLD_VERSION, [1, 2])

    etterlog += note

    etterlog.write(output.as_posix(), config)

    etterlog_updated = lief.parse(output.as_posix())

    assert lief.ELF.Note.TYPE.GNU_GOLD_VERSION in etterlog_updated

    # The string printed is largely irrelevant, but running print ensures no
    # regression occurs in a previous Note::dump segfault
    # https://github.com/lief-project/LIEF/issues/300
    with StringIO() as temp_stdout:
        with redirect_stdout(temp_stdout):
            print(etterlog)


def test_android_note(tmp_path: Path):
    ndkr16 = lief.parse(get_sample('ELF/ELF64_AArch64_piebinary_ndkr16.bin'))
    output = tmp_path / "etterlog"

    note: lief.ELF.AndroidIdent = ndkr16.get(lief.ELF.Note.TYPE.ANDROID_IDENT)
    assert note.sdk_version == 21
    assert note.ndk_version[:4] == "r16b"
    assert note.ndk_build_number[:7] == "4479499"

    note.sdk_version = 15
    note.ndk_version = "r15c"
    note.ndk_build_number = "123456"

    note = ndkr16.get(lief.ELF.Note.TYPE.ANDROID_IDENT)

    assert note.sdk_version == 15
    assert note.ndk_version[:4] == "r15c"
    assert note.ndk_build_number[:6] == "123456"

    ndkr16.write(output.as_posix(), config)

    ndkr15 = lief.parse(output.as_posix())

    note = ndkr15.get(lief.ELF.Note.TYPE.ANDROID_IDENT)

    assert note.sdk_version == 15
    assert note.ndk_version[:4] == "r15c"
    assert note.ndk_build_number[:6] == "123456"


def test_issue_816(tmp_path: Path):
    elf = lief.parse(get_sample('ELF/elf_notes_issue_816.bin'))
    output = tmp_path / "elf_notes_issue_816"

    assert len(elf.notes) == 40

    elf.write(output.as_posix(), config)
    new = lief.parse(output.as_posix())
    assert len(new.notes) == 40

def test_crashpad():
    RAW_CRASHPAD = "0900000008000000494e464f437261736870616400000000d85cf00300000000"
    note = lief.ELF.Note.create(bytes.fromhex(RAW_CRASHPAD))
    assert note.type == lief.ELF.Note.TYPE.CRASHPAD
    assert note.name == "Crashpad"
