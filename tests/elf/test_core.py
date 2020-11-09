#!/usr/bin/env python
import itertools
import logging
import os
import random
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import TestCase

import lief
from utils import get_sample

lief.logging.set_level(lief.logging.LOGGING_LEVEL.INFO)

class TestCore(TestCase):
    LOGGER = logging.getLogger(__name__)

    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_core_arm(self):
        core = lief.parse(get_sample('ELF/ELF32_ARM_core_hello.core'))

        notes = core.notes

        self.assertEqual(len(notes), 6)

        # Check NT_PRPSINFO
        # =================
        prpsinfo = notes[0]

        self.assertTrue(prpsinfo.is_core)
        self.assertEqual(prpsinfo.type_core, lief.ELF.NOTE_TYPES_CORE.PRPSINFO)

        # Check details
        details = prpsinfo.details
        self.assertIsInstance(details, lief.ELF.CorePrPsInfo)
        self.assertEqual(details.file_name, "hello-exe")
        self.assertEqual(details.uid,  2000)
        self.assertEqual(details.gid,  2000)
        self.assertEqual(details.pid,  8166)
        self.assertEqual(details.ppid, 8163)
        self.assertEqual(details.pgrp, 8166)
        self.assertEqual(details.sid,  7997)

        # Check NT_PRSTATUS
        # =================
        prstatus = notes[1]

        self.assertTrue(prstatus.is_core)
        self.assertEqual(prstatus.type_core, lief.ELF.NOTE_TYPES_CORE.PRSTATUS)

        # Check details
        details = prstatus.details

        self.assertEqual(details.current_sig, 7)
        self.assertEqual(details.sigpend, 0)
        self.assertEqual(details.sighold, 0)
        self.assertEqual(details.pid, 8166)
        self.assertEqual(details.ppid, 0)
        self.assertEqual(details.pgrp, 0)
        self.assertEqual(details.sid, 0)

        self.assertEqual(details.utime.sec, 0)
        self.assertEqual(details.utime.usec, 0)

        self.assertEqual(details.stime.sec, 0)
        self.assertEqual(details.stime.usec, 0)

        self.assertEqual(details.cutime.sec, 0)
        self.assertEqual(details.cutime.usec, 0)

        self.assertEqual(details.cstime.sec, 0)
        self.assertEqual(details.cstime.usec, 0)


        reg_ctx = details.register_context
        self.assertEqual(len(reg_ctx), 17)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R0], 0xaad75074)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R1], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R2], 0xb)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R3], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R4], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R5], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R6], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R7], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R8], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R9], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R10], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R11], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R12], 0xA)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R13], 1)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R14], 0xf7728841)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R15], 0xaad7507c)
        self.assertEqual(details.get(lief.ELF.CorePrStatus.REGISTERS.ARM_CPSR), 0x60010010)

        arm_vfp  = notes[2]

        # Check NT_NOTE
        # =================
        siginfo  = notes[3]
        self.assertTrue(siginfo.is_core)
        self.assertEqual(siginfo.type_core, lief.ELF.NOTE_TYPES_CORE.SIGINFO)

        # Check details
        details = siginfo.details
        self.assertEqual(details.signo, 7)
        self.assertEqual(details.sigcode, 0)
        self.assertEqual(details.sigerrno, 1)

        # Check NT_AUXV
        # =================
        auxv = notes[4]

        self.assertTrue(auxv.is_core)
        self.assertEqual(auxv.type_core, lief.ELF.NOTE_TYPES_CORE.AUXV)

        # Check details
        details = auxv.details

        self.assertEqual(len(details.values), 18)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.PHDR], 0xaad74034)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.PHENT], 0x20)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.PHNUM], 0x9)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.PAGESZ], 4096)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.BASE], 0xf7716000)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.FLAGS], 0)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.ENTRY], 0xaad75074)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.UID], 2000)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.EUID], 2000)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.GID], 2000)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.EGID], 2000)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.PLATFORM], 0xfffefb5c)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.HWCAP], 0x27b0d6)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.CKLTCK], 0x64)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.SECURE], 0)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.RANDOM], 0xfffefb4c)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.HWCAP2], 0x1f)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.EXECFN], 0xfffeffec)

        # Check NT_FILE
        # =================
        note = notes[5]

        self.assertTrue(note.is_core)
        self.assertEqual(note.type_core, lief.ELF.NOTE_TYPES_CORE.FILE)

        # Check details
        details = note.details
        files   = details.files

        self.assertEqual(len(files), len(details))
        self.assertEqual(21, len(details))

        self.assertEqual(files[0].start, 0xaad74000)
        self.assertEqual(files[0].end,   0xaad78000)
        self.assertEqual(files[0].file_ofs, 0)
        self.assertEqual(files[0].path, "/data/local/tmp/hello-exe")

        last = files.pop()

        self.assertEqual(last.start,    0xf77a1000)
        self.assertEqual(last.end,      0xf77a2000)
        self.assertEqual(last.file_ofs, 0x8a000)
        self.assertEqual(last.path, "/system/bin/linker")

        self.assertTrue(all(len(c.path) > 0 for c in details))


    def test_core_arm64(self):
        core = lief.parse(get_sample('ELF/ELF64_AArch64_core_hello.core'))

        notes = core.notes

        self.assertEqual(len(notes), 6)

        # Check NT_PRPSINFO
        # =================
        prpsinfo = notes[0]

        self.assertTrue(prpsinfo.is_core)
        self.assertEqual(prpsinfo.type_core, lief.ELF.NOTE_TYPES_CORE.PRPSINFO)

        # Check details
        details = prpsinfo.details
        self.assertIsInstance(details, lief.ELF.CorePrPsInfo)
        self.assertEqual(details.file_name, "hello-exe")
        self.assertEqual(details.uid,  2000)
        self.assertEqual(details.gid,  2000)
        self.assertEqual(details.pid,  8104)
        self.assertEqual(details.ppid, 8101)
        self.assertEqual(details.pgrp, 8104)
        self.assertEqual(details.sid,  7997)

        # Check NT_PRSTATUS
        # =================
        prstatus = notes[1]

        self.assertTrue(prstatus.is_core)
        self.assertEqual(prstatus.type_core, lief.ELF.NOTE_TYPES_CORE.PRSTATUS)

        # Check details
        details = prstatus.details

        self.assertEqual(details.current_sig, 5)
        self.assertEqual(details.sigpend, 0)
        self.assertEqual(details.sighold, 0)
        self.assertEqual(details.pid, 8104)
        self.assertEqual(details.ppid, 0)
        self.assertEqual(details.pgrp, 0)
        self.assertEqual(details.sid, 0)

        self.assertEqual(details.utime.sec, 0)
        self.assertEqual(details.utime.usec, 0)

        self.assertEqual(details.stime.sec, 0)
        self.assertEqual(details.stime.usec, 0)

        self.assertEqual(details.cutime.sec, 0)
        self.assertEqual(details.cutime.usec, 0)

        self.assertEqual(details.cstime.sec, 0)
        self.assertEqual(details.cstime.usec, 0)


        reg_ctx = details.register_context
        self.assertEqual(len(reg_ctx), 34)

        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X0],  0x5580b86f50)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X1],  0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X2],  0x1)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X3],  0x7fb7e2e160)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X4],  0x7fb7e83030)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X5],  0x4)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X6],  0x6f6c2f617461642f)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X7],  0x2f706d742f6c6163)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X8],  0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X9],  0xa)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X10], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X11], 0xA)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X12], 0x0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X13], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X14], 0x878ca62ae01a9a5)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X15], 0x7fb7e7a000)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X16], 0x7fb7c132c8)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X17], 0x7fb7bb0adc)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X18], 0x7fb7c1e000)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X19], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X20], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X21], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X22], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X23], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X24], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X25], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X26], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X27], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X28], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X29], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X30], 0x7fb7eb6068)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X31], 0x7ffffff950)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_PC],  0x5580b86f50)

        arm_vfp  = notes[2]

        # Check NT_NOTE
        # =================
        siginfo  = notes[3]
        self.assertTrue(siginfo.is_core)
        self.assertEqual(siginfo.type_core, lief.ELF.NOTE_TYPES_CORE.SIGINFO)

        # Check details
        details = siginfo.details
        self.assertEqual(details.signo, 5)
        self.assertEqual(details.sigcode, 0)
        self.assertEqual(details.sigerrno, 1)

        # Check NT_AUXV
        # =================
        auxv = notes[4]

        self.assertTrue(auxv.is_core)
        self.assertEqual(auxv.type_core, lief.ELF.NOTE_TYPES_CORE.AUXV)

        # Check details
        details = auxv.details

        self.assertEqual(len(details.values), 18)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.PHDR], 0x5580b86040)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.PHENT], 0x38)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.PHNUM], 0x9)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.PAGESZ], 4096)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.BASE], 0x7fb7e93000)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.FLAGS], 0)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.ENTRY], 0x5580b86f50)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.UID], 2000)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.EUID], 2000)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.GID], 2000)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.EGID], 2000)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.PLATFORM], 0x7ffffffb58)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.HWCAP], 0xff)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.CKLTCK], 0x64)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.SECURE], 0)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.RANDOM], 0x7ffffffb48)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.EXECFN], 0x7fffffffec)
        self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.SYSINFO_EHDR], 0x7fb7e91000)

        # Check NT_FILE
        # =================
        note = notes[5]

        self.assertTrue(note.is_core)
        self.assertEqual(note.type_core, lief.ELF.NOTE_TYPES_CORE.FILE)

        # Check details
        details = note.details
        files   = details.files

        self.assertEqual(len(files), len(details))
        self.assertEqual(22, len(details))

        self.assertEqual(files[0].start, 0x5580b86000)
        self.assertEqual(files[0].end,   0x5580b88000)
        self.assertEqual(files[0].file_ofs, 0)
        self.assertEqual(files[0].path, "/data/local/tmp/hello-exe")

        last = files.pop()
        self.assertEqual(last.start, 0x7fb7f8c000)
        self.assertEqual(last.end,   0x7fb7f8d000)
        self.assertEqual(last.file_ofs, 0xf8000)
        self.assertEqual(last.path, "/system/bin/linker64")

    def test_core_write(self):
        core = lief.parse(get_sample('ELF/ELF64_x86-64_core_hello.core'))
        note = core.notes[1]
        self.assertEqual(note.type_core, lief.ELF.NOTE_TYPES_CORE.PRSTATUS)
        details = note.details

        details[lief.ELF.CorePrStatus.REGISTERS.X86_64_RIP] = 0xBADC0DE

        note = core.notes[5]
        self.assertEqual(note.type_core, lief.ELF.NOTE_TYPES_CORE.AUXV)
        details = note.details

        details[lief.ELF.CoreAuxv.TYPES.ENTRY] = 0xBADC0DE

        note = core.notes[4]
        self.assertEqual(note.type_core, lief.ELF.NOTE_TYPES_CORE.SIGINFO)
        orig_siginfo_len = len(note.description)
        details = note.details

        details.sigerrno = 0xCC

        #  Cannot re-open a file on Windows, so handle it by hand
        with tempfile.NamedTemporaryFile(prefix="", suffix=".core", delete=False) as f:
            tmpfilename = f.name
            core.write(tmpfilename)
        try:
            with open(tmpfilename, 'rb') as f:
                core_new = lief.parse(f.name)
                self.assertIsNotNone(core_new)

                note = core_new.notes[1]
                self.assertEqual(note.type_core, lief.ELF.NOTE_TYPES_CORE.PRSTATUS)
                details = note.details

                self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.X86_64_RIP], 0xBADC0DE)

                note = core_new.notes[5]
                self.assertEqual(note.type_core, lief.ELF.NOTE_TYPES_CORE.AUXV)
                details = note.details

                self.assertEqual(details[lief.ELF.CoreAuxv.TYPES.ENTRY], 0xBADC0DE)

                note = core_new.notes[4]
                self.assertEqual(note.type_core, lief.ELF.NOTE_TYPES_CORE.SIGINFO)
                self.assertEqual(len(note.description), orig_siginfo_len)
                details = note.details

                self.assertEqual(details.sigerrno, 0xCC)
        finally:
            try:
                os.remove(tmpfilename)
            except OSError:
                pass


if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)
