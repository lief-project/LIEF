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
from contextlib import redirect_stdout
from io import StringIO
from unittest import TestCase

import lief
from utils import get_sample

lief.logging.set_level(lief.logging.LOGGING_LEVEL.INFO)

class TestNotes(TestCase):
    LOGGER = logging.getLogger(__name__)

    def setUp(self):
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def safe_delete(output):
        if os.path.isfile(output):
            try:
                os.remove(output)
                return True
            except Exception as e:
               TestNotes.LOGGER.error("Can't delete {} ({})".format(output, e))
               return False


    def test_change_note(self):
        _, output = tempfile.mkstemp(prefix="change_note_")

        etterlog = lief.parse(get_sample('ELF/ELF64_x86-64_binary_etterlog.bin'))
        build_id = etterlog[lief.ELF.NOTE_TYPES.BUILD_ID]

        new_desc = [i & 0xFF for i in range(500)]
        build_id.description = new_desc

        etterlog.write(output)

        etterlog_updated = lief.parse(output)

        self.assertEqual(etterlog[lief.ELF.NOTE_TYPES.BUILD_ID], etterlog_updated[lief.ELF.NOTE_TYPES.BUILD_ID])
        self.safe_delete(output)


    def test_remove_note(self):
        _, output = tempfile.mkstemp(prefix="remove_note_")
        self.logger.info("Output will be: {}".format(output))

        etterlog = lief.parse(get_sample('ELF/ELF64_x86-64_binary_etterlog.bin'))

        build_id = etterlog[lief.ELF.NOTE_TYPES.BUILD_ID]

        etterlog -= build_id

        etterlog.write(output)

        etterlog_updated = lief.parse(output)

        self.assertNotIn(lief.ELF.NOTE_TYPES.BUILD_ID, etterlog_updated)

        self.safe_delete(output)

    def test_add_note(self):
        _, output = tempfile.mkstemp(prefix="add_note_")
        self.logger.info("Output will be: {}".format(output))

        etterlog = lief.parse(get_sample('ELF/ELF64_x86-64_binary_etterlog.bin'))
        note = lief.ELF.Note("Foo", lief.ELF.NOTE_TYPES.GOLD_VERSION, [123])

        etterlog += note

        etterlog.write(output)

        etterlog_updated = lief.parse(output)

        self.assertIn(lief.ELF.NOTE_TYPES.GOLD_VERSION, etterlog_updated)

        self.safe_delete(output)

        # The string printed is largely irrelevant, but running print ensures no regression occurs in a previous Note::dump segfault
        # https://github.com/lief-project/LIEF/issues/300
        with StringIO() as temp_stdout:
            with redirect_stdout(temp_stdout):
                print(etterlog)


    def test_android_note(self):
        _, output = tempfile.mkstemp(prefix="android_note_")
        self.logger.info("Output will be: {}".format(output))

        ndkr16 = lief.parse(get_sample('ELF/ELF64_AArch64_piebinary_ndkr16.bin'))
        note = ndkr16.get(lief.ELF.NOTE_TYPES.ABI_TAG)
        details = note.details
        self.assertEqual(details.sdk_version, 21)
        self.assertEqual(details.ndk_version[:4], "r16b")
        self.assertEqual(details.ndk_build_number[:7], "4479499")

        details.sdk_version = 15
        details.ndk_version = "r15c"
        details.ndk_build_number = "123456"

        note = ndkr16.get(lief.ELF.NOTE_TYPES.ABI_TAG).details

        self.assertEqual(note.sdk_version, 15)
        self.assertEqual(note.ndk_version[:4], "r15c")
        self.assertEqual(note.ndk_build_number[:6], "123456")

        ndkr16.write(output)

        ndkr15 = lief.parse(output)

        note = ndkr15.get(lief.ELF.NOTE_TYPES.ABI_TAG).details

        self.assertEqual(note.sdk_version, 15)
        self.assertEqual(note.ndk_version[:4], "r15c")
        self.assertEqual(note.ndk_build_number[:6], "123456")

        self.safe_delete(output)


if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)
