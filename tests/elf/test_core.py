from pathlib import Path
from typing import cast

import lief
from utils import get_sample, parse_elf


def test_core_arm():
    core = parse_elf("ELF/ELF32_ARM_core_hello.core")

    notes = core.notes

    assert len(notes) == 6
    assert all(len(str(n).strip()) > 0 for n in notes), "\n".join(str(n) for n in notes)

    # Check NT_PRPSINFO
    # =================
    prpsinfo = cast(lief.ELF.CorePrPsInfo, notes[0])
    assert isinstance(prpsinfo, lief.ELF.CorePrPsInfo)

    assert prpsinfo.type == lief.ELF.Note.TYPE.CORE_PRPSINFO

    info = prpsinfo.info
    assert info is not None

    # Check details
    assert info.filename_stripped == "hello-exe"
    assert info.args_stripped == "./hello-exe "
    assert info.uid == 2000
    assert info.gid == 2000
    assert info.pid == 8166
    assert info.ppid == 8163
    assert info.pgrp == 8166
    assert info.sid == 7997

    # Check NT_PRSTATUS
    # =================
    prstatus = cast(lief.ELF.CorePrStatus, notes[1])

    assert prstatus.type == lief.ELF.Note.TYPE.CORE_PRSTATUS

    # Check details
    status = prstatus.status
    assert status.cursig == 7
    assert status.sigpend == 0
    assert status.sighold == 0
    assert status.pid == 8166
    assert status.ppid == 0
    assert status.pgrp == 0
    assert status.sid == 0

    assert status.utime.sec == 0
    assert status.utime.usec == 0

    assert status.stime.sec == 0
    assert status.stime.usec == 0

    assert status.cutime.sec == 0
    assert status.cutime.usec == 0

    assert status.cstime.sec == 0
    assert status.cstime.usec == 0

    reg_values = prstatus.register_values
    assert len(reg_values) == 17
    assert reg_values[lief.ELF.CorePrStatus.Registers.ARM.R0.value] == 0xAAD75074
    assert reg_values[lief.ELF.CorePrStatus.Registers.ARM.R1.value] == 0
    assert reg_values[lief.ELF.CorePrStatus.Registers.ARM.R2.value] == 0xB
    assert reg_values[lief.ELF.CorePrStatus.Registers.ARM.R3.value] == 0
    assert reg_values[lief.ELF.CorePrStatus.Registers.ARM.R4.value] == 0
    assert reg_values[lief.ELF.CorePrStatus.Registers.ARM.R5.value] == 0
    assert reg_values[lief.ELF.CorePrStatus.Registers.ARM.R6.value] == 0
    assert reg_values[lief.ELF.CorePrStatus.Registers.ARM.R7.value] == 0
    assert reg_values[lief.ELF.CorePrStatus.Registers.ARM.R8.value] == 0
    assert reg_values[lief.ELF.CorePrStatus.Registers.ARM.R9.value] == 0
    assert reg_values[lief.ELF.CorePrStatus.Registers.ARM.R10.value] == 0
    assert reg_values[lief.ELF.CorePrStatus.Registers.ARM.R11.value] == 0
    assert reg_values[lief.ELF.CorePrStatus.Registers.ARM.R12.value] == 0xA
    assert reg_values[lief.ELF.CorePrStatus.Registers.ARM.R13.value] == 1
    assert reg_values[lief.ELF.CorePrStatus.Registers.ARM.R14.value] == 0xF7728841
    assert reg_values[lief.ELF.CorePrStatus.Registers.ARM.R15.value] == 0xAAD7507C
    assert prstatus.get(lief.ELF.CorePrStatus.Registers.ARM.CPSR) == 0x60010010

    arm_vfp = notes[2]
    assert arm_vfp is not None

    siginfo = cast(lief.ELF.CoreSigInfo, notes[3])
    assert siginfo.type == lief.ELF.Note.TYPE.CORE_SIGINFO

    assert siginfo.signo == 7
    assert siginfo.sigcode == 0
    assert siginfo.sigerrno == 1

    # Check NT_AUXV
    # =================
    auxv = cast(lief.ELF.CoreAuxv, notes[4])

    assert auxv.type == lief.ELF.Note.TYPE.CORE_AUXV

    assert len(auxv.values) == 18
    assert auxv[lief.ELF.CoreAuxv.TYPE.PHDR] == 0xAAD74034
    assert auxv[lief.ELF.CoreAuxv.TYPE.PHENT] == 0x20
    assert auxv[lief.ELF.CoreAuxv.TYPE.PHNUM] == 0x9
    assert auxv[lief.ELF.CoreAuxv.TYPE.PAGESZ] == 4096
    assert auxv[lief.ELF.CoreAuxv.TYPE.BASE] == 0xF7716000
    assert auxv[lief.ELF.CoreAuxv.TYPE.FLAGS] == 0
    assert auxv[lief.ELF.CoreAuxv.TYPE.ENTRY] == 0xAAD75074
    assert auxv[lief.ELF.CoreAuxv.TYPE.UID] == 2000
    assert auxv[lief.ELF.CoreAuxv.TYPE.EUID] == 2000
    assert auxv[lief.ELF.CoreAuxv.TYPE.GID] == 2000
    assert auxv[lief.ELF.CoreAuxv.TYPE.EGID] == 2000
    assert auxv[lief.ELF.CoreAuxv.TYPE.TGT_PLATFORM] == 0xFFFEFB5C
    assert auxv[lief.ELF.CoreAuxv.TYPE.HWCAP] == 0x27B0D6
    assert auxv[lief.ELF.CoreAuxv.TYPE.CLKTCK] == 0x64
    assert auxv[lief.ELF.CoreAuxv.TYPE.SECURE] == 0
    assert auxv[lief.ELF.CoreAuxv.TYPE.RANDOM] == 0xFFFEFB4C
    assert auxv[lief.ELF.CoreAuxv.TYPE.HWCAP2] == 0x1F
    assert auxv[lief.ELF.CoreAuxv.TYPE.EXECFN] == 0xFFFEFFEC

    # Check NT_FILE
    # =================
    note = cast(lief.ELF.CoreFile, notes[5])

    assert note.type == lief.ELF.Note.TYPE.CORE_FILE

    # Check details
    files = note.files

    assert len(files) == len(note)
    assert 21 == len(note)

    assert files[0].start == 0xAAD74000
    assert files[0].end == 0xAAD78000
    assert files[0].file_ofs == 0
    assert files[0].path == "/data/local/tmp/hello-exe"

    last = files.pop()

    assert last.start == 0xF77A1000
    assert last.end == 0xF77A2000
    assert last.file_ofs == 0x8A000
    assert last.path == "/system/bin/linker"

    assert all(len(c.path) > 0 for c in note)


def test_core_arm64():
    core = lief.ELF.parse(get_sample("ELF/ELF64_AArch64_core_hello.core"))
    assert core is not None

    notes = core.notes

    assert len(notes) == 6

    assert all(len(str(n).strip()) > 0 for n in notes)

    # Check NT_PRPSINFO
    # =================
    prpsinfo = cast(lief.ELF.CorePrPsInfo, notes[0])

    assert prpsinfo.type == lief.ELF.Note.TYPE.CORE_PRPSINFO

    # Check details
    assert isinstance(prpsinfo, lief.ELF.CorePrPsInfo)
    info = prpsinfo.info
    assert info is not None
    assert info.filename_stripped == "hello-exe"
    assert info.args_stripped == "./hello-exe "
    assert info.uid == 2000
    assert info.gid == 2000
    assert info.pid == 8104
    assert info.ppid == 8101
    assert info.pgrp == 8104
    assert info.sid == 7997

    # Check NT_PRSTATUS
    # =================
    prstatus = cast(lief.ELF.CorePrStatus, notes[1])

    assert prstatus.type == lief.ELF.Note.TYPE.CORE_PRSTATUS

    # Check details
    status = prstatus.status

    assert status.cursig == 5
    assert status.sigpend == 0
    assert status.sighold == 0
    assert status.pid == 8104
    assert status.ppid == 0
    assert status.pgrp == 0
    assert status.sid == 0

    assert status.utime.sec == 0
    assert status.utime.usec == 0

    assert status.stime.sec == 0
    assert status.stime.usec == 0

    assert status.cutime.sec == 0
    assert status.cutime.usec == 0

    assert status.cstime.sec == 0
    assert status.cstime.usec == 0

    regs = prstatus.register_values
    assert len(regs) == 34

    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X0.value] == 0x5580B86F50
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X1.value] == 0
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X2.value] == 0x1
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X3.value] == 0x7FB7E2E160
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X4.value] == 0x7FB7E83030
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X5.value] == 0x4
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X6.value] == 0x6F6C2F617461642F
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X7.value] == 0x2F706D742F6C6163
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X8.value] == 0
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X9.value] == 0xA
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X10.value] == 0
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X11.value] == 0xA
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X12.value] == 0x0
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X13.value] == 0
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X14.value] == 0x878CA62AE01A9A5
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X15.value] == 0x7FB7E7A000
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X16.value] == 0x7FB7C132C8
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X17.value] == 0x7FB7BB0ADC
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X18.value] == 0x7FB7C1E000
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X19.value] == 0
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X20.value] == 0
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X21.value] == 0
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X22.value] == 0
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X23.value] == 0
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X24.value] == 0
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X25.value] == 0
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X26.value] == 0
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X27.value] == 0
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X28.value] == 0
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X29.value] == 0
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X30.value] == 0x7FB7EB6068
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.X31.value] == 0x7FFFFFF950
    assert regs[lief.ELF.CorePrStatus.Registers.AARCH64.PC.value] == 0x5580B86F50

    fpregset = notes[2]
    assert fpregset.type == lief.ELF.Note.TYPE.CORE_FPREGSET

    # Check NT_NOTE
    # =================
    siginfo = notes[3]
    assert siginfo.type == lief.ELF.Note.TYPE.CORE_SIGINFO

    assert isinstance(siginfo, lief.ELF.CoreSigInfo)

    assert siginfo.signo == 5
    assert siginfo.sigcode == 0
    assert siginfo.sigerrno == 1

    # Check NT_AUXV
    # =================
    auxv = cast(lief.ELF.CoreAuxv, notes[4])

    assert auxv.type == lief.ELF.Note.TYPE.CORE_AUXV
    assert isinstance(auxv, lief.ELF.CoreAuxv)

    # Check details
    values = auxv.values
    assert len(values) == 18
    assert values[lief.ELF.CoreAuxv.TYPE.PHDR] == 0x5580B86040
    assert values[lief.ELF.CoreAuxv.TYPE.PHENT] == 0x38
    assert values[lief.ELF.CoreAuxv.TYPE.PHNUM] == 0x9
    assert values[lief.ELF.CoreAuxv.TYPE.PAGESZ] == 4096
    assert values[lief.ELF.CoreAuxv.TYPE.BASE] == 0x7FB7E93000
    assert values[lief.ELF.CoreAuxv.TYPE.FLAGS] == 0
    assert values[lief.ELF.CoreAuxv.TYPE.ENTRY] == 0x5580B86F50
    assert values[lief.ELF.CoreAuxv.TYPE.UID] == 2000
    assert values[lief.ELF.CoreAuxv.TYPE.EUID] == 2000
    assert values[lief.ELF.CoreAuxv.TYPE.GID] == 2000
    assert values[lief.ELF.CoreAuxv.TYPE.EGID] == 2000
    assert values[lief.ELF.CoreAuxv.TYPE.TGT_PLATFORM] == 0x7FFFFFFB58
    assert values[lief.ELF.CoreAuxv.TYPE.HWCAP] == 0xFF
    assert values[lief.ELF.CoreAuxv.TYPE.CLKTCK] == 0x64
    assert values[lief.ELF.CoreAuxv.TYPE.SECURE] == 0
    assert values[lief.ELF.CoreAuxv.TYPE.RANDOM] == 0x7FFFFFFB48
    assert values[lief.ELF.CoreAuxv.TYPE.EXECFN] == 0x7FFFFFFFEC
    assert values[lief.ELF.CoreAuxv.TYPE.SYSINFO_EHDR] == 0x7FB7E91000

    # Check NT_FILE
    # =================
    note = cast(lief.ELF.CoreFile, notes[5])

    assert note.type == lief.ELF.Note.TYPE.CORE_FILE

    assert isinstance(note, lief.ELF.CoreFile)

    files = note.files
    assert len(files) == len(note)
    assert 22 == len(files)

    assert files[0].start == 0x5580B86000
    assert files[0].end == 0x5580B88000
    assert files[0].file_ofs == 0
    assert files[0].path == "/data/local/tmp/hello-exe"

    last = files.pop()
    assert last.start == 0x7FB7F8C000
    assert last.end == 0x7FB7F8D000
    assert last.file_ofs == 0xF8000
    assert last.path == "/system/bin/linker64"


def test_core_write(tmp_path: Path):
    core = lief.ELF.parse(get_sample("ELF/ELF64_x86-64_core_hello.core"))
    assert core is not None
    note = core.notes[1]

    assert isinstance(note, lief.ELF.CorePrStatus)
    assert note.type == lief.ELF.Note.TYPE.CORE_PRSTATUS

    note[lief.ELF.CorePrStatus.Registers.X86_64.RIP] = 0xBADC0DE

    note = core.notes[5]
    assert isinstance(note, lief.ELF.CoreAuxv)
    assert note.type == lief.ELF.Note.TYPE.CORE_AUXV

    note[lief.ELF.CoreAuxv.TYPE.ENTRY] = 0xBADC0DE

    note = core.notes[4]
    assert isinstance(note, lief.ELF.CoreSigInfo)
    assert note.type == lief.ELF.Note.TYPE.CORE_SIGINFO
    orig_siginfo_len = len(note.description)
    note.sigerrno = 0xCC

    output = tmp_path / "elf.core"

    #  Cannot reopen a file on Windows, so handle it by hand
    core.write(output)
    core_new = lief.ELF.parse(output)
    assert core_new is not None

    note = core_new.notes[1]
    assert note.type == lief.ELF.Note.TYPE.CORE_PRSTATUS
    assert isinstance(note, lief.ELF.CorePrStatus)
    assert note[lief.ELF.CorePrStatus.Registers.X86_64.RIP] == 0xBADC0DE

    note = core_new.notes[5]
    assert isinstance(note, lief.ELF.CoreAuxv)
    assert note.type == lief.ELF.Note.TYPE.CORE_AUXV

    assert note[lief.ELF.CoreAuxv.TYPE.ENTRY] == 0xBADC0DE

    note = core_new.notes[4]

    assert isinstance(note, lief.ELF.CoreSigInfo)
    assert note.type == lief.ELF.Note.TYPE.CORE_SIGINFO
    assert len(note.description) == orig_siginfo_len

    assert note.sigerrno == 0xCC
