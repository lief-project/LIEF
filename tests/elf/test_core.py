#!/usr/bin/env python
from pathlib import Path

import lief
from utils import get_sample

lief.logging.set_level(lief.logging.LOGGING_LEVEL.INFO)

def test_core_arm():
    core = lief.parse(get_sample('ELF/ELF32_ARM_core_hello.core'))

    notes = core.notes

    assert len(notes) == 6

    # Check NT_PRPSINFO
    # =================
    prpsinfo = notes[0]

    assert prpsinfo.is_core
    assert prpsinfo.type_core == lief.ELF.NOTE_TYPES_CORE.PRPSINFO

    # Check details
    details = prpsinfo.details
    assert isinstance(details, lief.ELF.CorePrPsInfo)

    assert details.file_name == "hello-exe"
    assert details.uid  == 2000
    assert details.gid  == 2000
    assert details.pid  == 8166
    assert details.ppid == 8163
    assert details.pgrp == 8166
    assert details.sid  == 7997

    # Check NT_PRSTATUS
    # =================
    prstatus = notes[1]

    assert prstatus.is_core
    assert prstatus.type_core == lief.ELF.NOTE_TYPES_CORE.PRSTATUS

    # Check details
    details = prstatus.details

    assert details.current_sig == 7
    assert details.sigpend == 0
    assert details.sighold == 0
    assert details.pid == 8166
    assert details.ppid == 0
    assert details.pgrp == 0
    assert details.sid == 0

    assert details.utime.sec == 0
    assert details.utime.usec == 0

    assert details.stime.sec == 0
    assert details.stime.usec == 0

    assert details.cutime.sec == 0
    assert details.cutime.usec == 0

    assert details.cstime.sec == 0
    assert details.cstime.usec == 0

    reg_ctx = details.register_context
    assert len(reg_ctx) == 17
    assert details[lief.ELF.CorePrStatus.REGISTERS.ARM_R0] == 0xaad75074
    assert details[lief.ELF.CorePrStatus.REGISTERS.ARM_R1] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.ARM_R2] == 0xb
    assert details[lief.ELF.CorePrStatus.REGISTERS.ARM_R3] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.ARM_R4] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.ARM_R5] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.ARM_R6] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.ARM_R7] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.ARM_R8] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.ARM_R9] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.ARM_R10] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.ARM_R11] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.ARM_R12] == 0xA
    assert details[lief.ELF.CorePrStatus.REGISTERS.ARM_R13] == 1
    assert details[lief.ELF.CorePrStatus.REGISTERS.ARM_R14] == 0xf7728841
    assert details[lief.ELF.CorePrStatus.REGISTERS.ARM_R15] == 0xaad7507c
    assert details.get(lief.ELF.CorePrStatus.REGISTERS.ARM_CPSR) == 0x60010010

    arm_vfp  = notes[2]

    # Check NT_NOTE
    # =================
    siginfo  = notes[3]
    assert siginfo.is_core
    assert siginfo.type_core == lief.ELF.NOTE_TYPES_CORE.SIGINFO

    # Check details
    details = siginfo.details
    assert details.signo == 7
    assert details.sigcode == 0
    assert details.sigerrno == 1

    # Check NT_AUXV
    # =================
    auxv = notes[4]

    assert auxv.is_core
    assert auxv.type_core == lief.ELF.NOTE_TYPES_CORE.AUXV

    # Check details
    details = auxv.details

    assert len(details.values) == 18
    assert details[lief.ELF.CoreAuxv.TYPES.PHDR] == 0xaad74034
    assert details[lief.ELF.CoreAuxv.TYPES.PHENT] == 0x20
    assert details[lief.ELF.CoreAuxv.TYPES.PHNUM] == 0x9
    assert details[lief.ELF.CoreAuxv.TYPES.PAGESZ] == 4096
    assert details[lief.ELF.CoreAuxv.TYPES.BASE] == 0xf7716000
    assert details[lief.ELF.CoreAuxv.TYPES.FLAGS] == 0
    assert details[lief.ELF.CoreAuxv.TYPES.ENTRY] == 0xaad75074
    assert details[lief.ELF.CoreAuxv.TYPES.UID] == 2000
    assert details[lief.ELF.CoreAuxv.TYPES.EUID] == 2000
    assert details[lief.ELF.CoreAuxv.TYPES.GID] == 2000
    assert details[lief.ELF.CoreAuxv.TYPES.EGID] == 2000
    assert details[lief.ELF.CoreAuxv.TYPES.PLATFORM] == 0xfffefb5c
    assert details[lief.ELF.CoreAuxv.TYPES.HWCAP] == 0x27b0d6
    assert details[lief.ELF.CoreAuxv.TYPES.CKLTCK] == 0x64
    assert details[lief.ELF.CoreAuxv.TYPES.SECURE] == 0
    assert details[lief.ELF.CoreAuxv.TYPES.RANDOM] == 0xfffefb4c
    assert details[lief.ELF.CoreAuxv.TYPES.HWCAP2] == 0x1f
    assert details[lief.ELF.CoreAuxv.TYPES.EXECFN] == 0xfffeffec

    # Check NT_FILE
    # =================
    note = notes[5]

    assert note.is_core
    assert note.type_core == lief.ELF.NOTE_TYPES_CORE.FILE

    # Check details
    details = note.details
    files   = details.files

    assert len(files) == len(details)
    assert 21 == len(details)

    assert files[0].start == 0xaad74000
    assert files[0].end == 0xaad78000
    assert files[0].file_ofs == 0
    assert files[0].path == "/data/local/tmp/hello-exe"

    last = files.pop()

    assert last.start == 0xf77a1000
    assert last.end == 0xf77a2000
    assert last.file_ofs == 0x8a000
    assert last.path == "/system/bin/linker"

    assert all(len(c.path) > 0 for c in details)


def test_core_arm64():
    core = lief.parse(get_sample('ELF/ELF64_AArch64_core_hello.core'))

    notes = core.notes

    assert len(notes) == 6

    # Check NT_PRPSINFO
    # =================
    prpsinfo = notes[0]

    assert prpsinfo.is_core
    assert prpsinfo.type_core == lief.ELF.NOTE_TYPES_CORE.PRPSINFO

    # Check details
    details = prpsinfo.details
    assert isinstance(details, lief.ELF.CorePrPsInfo)
    assert details.file_name == "hello-exe"
    assert details.uid == 2000
    assert details.gid == 2000
    assert details.pid == 8104
    assert details.ppid == 8101
    assert details.pgrp == 8104
    assert details.sid == 7997

    # Check NT_PRSTATUS
    # =================
    prstatus = notes[1]

    assert prstatus.is_core
    assert prstatus.type_core == lief.ELF.NOTE_TYPES_CORE.PRSTATUS

    # Check details
    details = prstatus.details

    assert details.current_sig == 5
    assert details.sigpend == 0
    assert details.sighold == 0
    assert details.pid == 8104
    assert details.ppid == 0
    assert details.pgrp == 0
    assert details.sid == 0

    assert details.utime.sec == 0
    assert details.utime.usec == 0

    assert details.stime.sec == 0
    assert details.stime.usec == 0

    assert details.cutime.sec == 0
    assert details.cutime.usec == 0

    assert details.cstime.sec == 0
    assert details.cstime.usec == 0


    reg_ctx = details.register_context
    assert len(reg_ctx) == 34

    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X0] == 0x5580b86f50
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X1] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X2] == 0x1
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X3] == 0x7fb7e2e160
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X4] == 0x7fb7e83030
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X5] == 0x4
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X6] == 0x6f6c2f617461642f
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X7] == 0x2f706d742f6c6163
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X8] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X9] == 0xa
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X10] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X11] == 0xA
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X12] == 0x0
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X13] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X14] == 0x878ca62ae01a9a5
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X15] == 0x7fb7e7a000
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X16] == 0x7fb7c132c8
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X17] == 0x7fb7bb0adc
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X18] == 0x7fb7c1e000
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X19] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X20] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X21] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X22] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X23] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X24] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X25] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X26] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X27] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X28] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X29] == 0
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X30] == 0x7fb7eb6068
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X31] == 0x7ffffff950
    assert details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_PC] == 0x5580b86f50

    arm_vfp  = notes[2]

    # Check NT_NOTE
    # =================
    siginfo  = notes[3]
    assert siginfo.is_core
    assert siginfo.type_core == lief.ELF.NOTE_TYPES_CORE.SIGINFO

    # Check details
    details = siginfo.details
    assert details.signo == 5
    assert details.sigcode == 0
    assert details.sigerrno == 1

    # Check NT_AUXV
    # =================
    auxv = notes[4]

    assert auxv.is_core
    assert auxv.type_core == lief.ELF.NOTE_TYPES_CORE.AUXV

    # Check details
    details = auxv.details

    assert len(details.values) == 18
    assert details[lief.ELF.CoreAuxv.TYPES.PHDR] == 0x5580b86040
    assert details[lief.ELF.CoreAuxv.TYPES.PHENT] == 0x38
    assert details[lief.ELF.CoreAuxv.TYPES.PHNUM] == 0x9
    assert details[lief.ELF.CoreAuxv.TYPES.PAGESZ] == 4096
    assert details[lief.ELF.CoreAuxv.TYPES.BASE] == 0x7fb7e93000
    assert details[lief.ELF.CoreAuxv.TYPES.FLAGS] == 0
    assert details[lief.ELF.CoreAuxv.TYPES.ENTRY] == 0x5580b86f50
    assert details[lief.ELF.CoreAuxv.TYPES.UID] == 2000
    assert details[lief.ELF.CoreAuxv.TYPES.EUID] == 2000
    assert details[lief.ELF.CoreAuxv.TYPES.GID] == 2000
    assert details[lief.ELF.CoreAuxv.TYPES.EGID] == 2000
    assert details[lief.ELF.CoreAuxv.TYPES.PLATFORM] == 0x7ffffffb58
    assert details[lief.ELF.CoreAuxv.TYPES.HWCAP] == 0xff
    assert details[lief.ELF.CoreAuxv.TYPES.CKLTCK] == 0x64
    assert details[lief.ELF.CoreAuxv.TYPES.SECURE] == 0
    assert details[lief.ELF.CoreAuxv.TYPES.RANDOM] == 0x7ffffffb48
    assert details[lief.ELF.CoreAuxv.TYPES.EXECFN] == 0x7fffffffec
    assert details[lief.ELF.CoreAuxv.TYPES.SYSINFO_EHDR] == 0x7fb7e91000

    # Check NT_FILE
    # =================
    note = notes[5]

    assert note.is_core
    assert note.type_core == lief.ELF.NOTE_TYPES_CORE.FILE

    # Check details
    details = note.details
    files   = details.files

    assert len(files) == len(details)
    assert 22 == len(details)

    assert files[0].start == 0x5580b86000
    assert files[0].end == 0x5580b88000
    assert files[0].file_ofs == 0
    assert files[0].path == "/data/local/tmp/hello-exe"

    last = files.pop()
    assert last.start == 0x7fb7f8c000
    assert last.end == 0x7fb7f8d000
    assert last.file_ofs == 0xf8000
    assert last.path == "/system/bin/linker64"

def test_core_write(tmp_path: Path):
    core = lief.parse(get_sample('ELF/ELF64_x86-64_core_hello.core'))
    note = core.notes[1]
    assert note.type_core == lief.ELF.NOTE_TYPES_CORE.PRSTATUS
    details = note.details

    details[lief.ELF.CorePrStatus.REGISTERS.X86_64_RIP] = 0xBADC0DE

    note = core.notes[5]
    assert note.type_core == lief.ELF.NOTE_TYPES_CORE.AUXV
    details = note.details

    details[lief.ELF.CoreAuxv.TYPES.ENTRY] = 0xBADC0DE

    note = core.notes[4]
    assert note.type_core == lief.ELF.NOTE_TYPES_CORE.SIGINFO
    orig_siginfo_len = len(note.description)
    details = note.details

    details.sigerrno = 0xCC

    output = tmp_path / "elf.core"

    config = lief.ELF.Builder.config_t()
    config.notes = True

    #  Cannot re-open a file on Windows, so handle it by hand
    core.write(output.as_posix(), config)
    core_new = lief.parse(output.as_posix())
    assert core_new is not None

    note = core_new.notes[1]
    assert note.type_core == lief.ELF.NOTE_TYPES_CORE.PRSTATUS
    details = note.details

    assert details[lief.ELF.CorePrStatus.REGISTERS.X86_64_RIP] == 0xBADC0DE

    note = core_new.notes[5]
    assert note.type_core == lief.ELF.NOTE_TYPES_CORE.AUXV
    details = note.details

    assert details[lief.ELF.CoreAuxv.TYPES.ENTRY] == 0xBADC0DE

    note = core_new.notes[4]
    assert note.type_core == lief.ELF.NOTE_TYPES_CORE.SIGINFO
    assert len(note.description) == orig_siginfo_len
    details = note.details

    assert details.sigerrno == 0xCC
