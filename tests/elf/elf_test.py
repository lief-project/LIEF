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
from subprocess import Popen
from unittest import TestCase

import lief
from utils import get_sample, has_recent_glibc, is_linux, is_x86_64

lief.logging.set_level(lief.logging.LOGGING_LEVEL.INFO)

class TestELF(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_rpath(self):
        etterlog = lief.parse(get_sample('ELF/ELF64_x86-64_binary_etterlog.bin'))

        dynamic_entries = etterlog.dynamic_entries

        rpath = [e for e in dynamic_entries if e.tag == lief.ELF.DYNAMIC_TAGS.RPATH]

        self.assertEqual(len(rpath), 1)
        rpath = rpath.pop()

        self.assertEqual(rpath.name, "/usr/lib")

    def test_runpath(self):
        etterlog = lief.parse(get_sample('ELF/ELF64_x86-64_binary_systemd-resolve.bin'))

        dynamic_entries = etterlog.dynamic_entries

        runpath = [e for e in dynamic_entries if e.tag == lief.ELF.DYNAMIC_TAGS.RUNPATH]

        self.assertEqual(len(runpath), 1)
        runpath = runpath.pop()

        self.assertEqual(runpath.name, "/usr/lib/systemd")


    def test_gnuhash(self):
        ls = lief.parse(get_sample('ELF/ELF64_x86-64_binary_ls.bin'))
        gnu_hash = ls.gnu_hash

        self.assertEqual(gnu_hash.nb_buckets, 33)
        self.assertEqual(gnu_hash.symbol_index, 109)
        self.assertEqual(gnu_hash.shift2, 7)

        bloom_filters = gnu_hash.bloom_filters

        self.assertEqual(len(bloom_filters), 2)
        self.assertIn(0x3FAE01120C48A1A6, bloom_filters)
        self.assertIn(0x900004A81310D428, bloom_filters)

        buckets = gnu_hash.buckets
        self.assertEqual(len(buckets), 33)

        buckets_test = [109, 110, 0, 0, 0, 0, 0, 111, 113, 114, 0, 0, 0, 115, 0, 116, 0, 0, 117, 118, 119, 0, 120, 0, 0, 121, 123, 124, 126, 128, 129, 130, 0]
        self.assertEqual(buckets_test, buckets)


        hash_values = gnu_hash.hash_values
        hash_values_test = [0x60E0C78D, 0xF54162E5, 0x7FFD8E4E, 0x1C8BF239, 0xEEFD3EB, 0x1C8C1D29, 0x1C5871D9,
                0x5B7F3E03, 0x759A6A7F, 0xEF18DB9, 0xBA53E4D, 0x9789A097, 0x9E7650BC, 0xD39AD3D,
                0x12F7C433, 0xEB01FAB6, 0xECD54543, 0xAD3C9892, 0x72632CCF, 0x12F7A2B3, 0x7C92E3BB, 0x7C96F087]
        self.assertEqual(hash_values, hash_values_test)

        #for s in list(ls.dynamic_symbols)[gnu_hash.symbol_index:]:
        #    print(gnu_hash.check(s.name), s.name)
        self.assertTrue(all(gnu_hash.check(x.name) for x in list(ls.dynamic_symbols)[gnu_hash.symbol_index:]))

        self.assertFalse(gnu_hash.check("foofdsfdsfds"))
        self.assertFalse(gnu_hash.check("fazertrvkdfsrezklqpfjeopqdi"))

    @unittest.skipUnless(is_linux() and is_x86_64(), "requires Linux x86-64")
    @unittest.skipUnless(has_recent_glibc(), "Need a recent GLIBC version")
    def test_permutation(self):
        samples = [
                "ELF/ELF64_x86-64_binary_ls.bin",
                #"ELF/ELF64_x86-64_binary_gcc.bin",
                #"ELF/ELF64_x86-64_binary_openssl.bin",
        ]
        tmp_dir = tempfile.mkdtemp(suffix='_lief_test_permutation')
        for sample in samples:
            binary = lief.parse(get_sample(sample))
            dynamic_symbols = binary.dynamic_symbols

            gnu_hash_table = binary.gnu_hash

            idx = gnu_hash_table.symbol_index

            permutation = [i for i in range(1, len(dynamic_symbols))]
            random.shuffle(permutation)
            permutation = [0] + permutation
            binary.permute_dynamic_symbols(permutation)

            builder = lief.ELF.Builder(binary)
            builder.build()
            output = os.path.join(tmp_dir, "{}.permutated".format(binary.name))
            self.logger.debug("Output: {}".format(output))
            builder.write(output)

            if not sys.platform.startswith("linux"):
                return

            st = os.stat(output)
            os.chmod(output, st.st_mode | stat.S_IEXEC)

            p = Popen([output, "--help"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            stdout, _ = p.communicate()
            self.logger.debug(stdout.decode("utf8"))
            self.assertEqual(p.returncode, 0)

    def test_notes(self):
        systemd_resolve = lief.parse(get_sample('ELF/ELF64_x86-64_binary_systemd-resolve.bin'))
        notes = systemd_resolve.notes
        self.assertEqual(len(notes), 3)

        n1 = notes[0]
        n2 = notes[1]
        n3 = notes[2]

        self.assertEqual(n1.name, "GNU")
        self.assertEqual(n2.name, "GNU")
        self.assertEqual(n3.name, "GNU")

        self.assertEqual(n1.type, lief.ELF.NOTE_TYPES.ABI_TAG)
        self.assertEqual(n2.type, lief.ELF.NOTE_TYPES.BUILD_ID)
        self.assertEqual(n3.type, lief.ELF.NOTE_TYPES.GOLD_VERSION)

        self.assertEqual(n1.details.abi, lief.ELF.NOTE_ABIS.LINUX)
        self.assertEqual(n1.details.version, [2, 6, 32])

        self.assertEqual(list(n2.description), [
            0x7e, 0x68, 0x6c, 0x7d,
            0x79, 0x9b, 0xa4, 0xcd,
            0x32, 0xa2, 0x34, 0xe8,
            0x4f, 0xd7, 0x45, 0x98,
            0x21, 0x32, 0x9d, 0xc8
            ])

        self.assertEqual("".join(map(chr, n3.description)), "gold 1.12\x00\x00\x00")

    def test_symbols_access(self):
        hello = lief.parse(get_sample('ELF/ELF64_x86-64_binary_hello-gdb.bin'))

        symbols         = hello.symbols
        dynamic_symbols = hello.dynamic_symbols
        static_symbols  = hello.static_symbols

        self.assertTrue(all(s in symbols for s in dynamic_symbols))
        self.assertTrue(all(s in symbols for s in static_symbols))

    def test_relocation_size(self):
        aarch64_toybox = lief.parse(get_sample('ELF/ELF64_AARCH64_piebinary_toybox.pie'))
        arm_ls         = lief.parse(get_sample('ELF/ELF32_ARM_binary_ls.bin'))
        x86_ls         = lief.parse(get_sample('ELF/ELF32_x86_binary_ls.bin'))
        x86_64_ls      = lief.parse(get_sample('ELF/ELF64_x86-64_binary_ld.bin'))

        for r in itertools.chain(aarch64_toybox.dynamic_relocations, aarch64_toybox.pltgot_relocations):
            if lief.ELF.RELOCATION_AARCH64(r.type) == lief.ELF.RELOCATION_AARCH64.RELATIVE:
                self.assertEqual(r.size, 64)

            if lief.ELF.RELOCATION_AARCH64(r.type) == lief.ELF.RELOCATION_AARCH64.GLOB_DAT:
                self.assertEqual(r.size, 64)

            if lief.ELF.RELOCATION_AARCH64(r.type) == lief.ELF.RELOCATION_AARCH64.JUMP_SLOT:
                self.assertEqual(r.size, 64)

        for r in itertools.chain(arm_ls.dynamic_relocations, arm_ls.pltgot_relocations):
            if lief.ELF.RELOCATION_ARM(r.type) == lief.ELF.RELOCATION_ARM.RELATIVE:
                self.assertEqual(r.size, 32)

            if lief.ELF.RELOCATION_ARM(r.type) == lief.ELF.RELOCATION_ARM.GLOB_DAT:
                self.assertEqual(r.size, 32)

            if lief.ELF.RELOCATION_ARM(r.type) == lief.ELF.RELOCATION_ARM.ABS32:
                self.assertEqual(r.size, 32)

            if lief.ELF.RELOCATION_ARM(r.type) == lief.ELF.RELOCATION_ARM.JUMP_SLOT:
                self.assertEqual(r.size, 32)


        for r in itertools.chain(x86_ls.dynamic_relocations, x86_ls.pltgot_relocations):
            if lief.ELF.RELOCATION_i386(r.type) == lief.ELF.RELOCATION_i386.GLOB_DAT:
                self.assertEqual(r.size, 32)

            if lief.ELF.RELOCATION_i386(r.type) == lief.ELF.RELOCATION_i386.COPY:
                self.assertEqual(r.size, 32)

            if lief.ELF.RELOCATION_i386(r.type) == lief.ELF.RELOCATION_i386.JUMP_SLOT:
                self.assertEqual(r.size, 32)


        for r in itertools.chain(x86_64_ls.dynamic_relocations, x86_64_ls.pltgot_relocations):
            if lief.ELF.RELOCATION_X86_64(r.type) == lief.ELF.RELOCATION_X86_64.GLOB_DAT:
                self.assertEqual(r.size, 64)

            if lief.ELF.RELOCATION_X86_64(r.type) == lief.ELF.RELOCATION_X86_64.COPY:
                self.assertEqual(r.size, 32)

            if lief.ELF.RELOCATION_X86_64(r.type) == lief.ELF.RELOCATION_X86_64.JUMP_SLOT:
                self.assertEqual(r.size, 64)

    def test_sectionless(self):
        sample = "ELF/ELF64_x86-64_binary_rvs.bin"
        rvs = lief.parse(get_sample(sample))
        dynsym = list(rvs.dynamic_symbols)
        self.assertEqual(len(dynsym), 10)

    def test_dynamic_flags(self):
        sample = "ELF/ELF32_ARM_binary_ls.bin"
        ls = lief.parse(get_sample(sample))
        d_flags = ls.get(lief.ELF.DYNAMIC_TAGS.FLAGS)
        d_flags_1 = ls.get(lief.ELF.DYNAMIC_TAGS.FLAGS_1)

        self.assertIn(lief.ELF.DYNAMIC_FLAGS.BIND_NOW, d_flags)
        self.assertIn(lief.ELF.DYNAMIC_FLAGS_1.NOW, d_flags_1)


    def test_unwind_arm(self):
        sample = "ELF/ELF32_ARM_binary_ls.bin"
        ls = lief.parse(get_sample(sample))

        functions = sorted(ls.functions, key=lambda f: f.address)

        self.assertEqual(len(functions), 265)

        self.assertEqual(functions[0].address, 19684)
        self.assertEqual(functions[0].size,    0)
        self.assertEqual(functions[0].name,    "open")

        self.assertEqual(functions[-1].address, 102372)
        self.assertEqual(functions[-1].size,    0)
        self.assertEqual(functions[-1].name,    "")


    def test_unwind_x86(self):
        sample = "ELF/ELF64_x86-64_binary_ld.bin"
        ld = lief.parse(get_sample(sample))

        functions = sorted(ld.functions, key=lambda f: f.address)

        self.assertEqual(len(functions), 503)

        self.assertEqual(functions[0].address, 4209304)
        self.assertEqual(functions[0].size,    0)
        self.assertEqual(functions[0].name,    "_init")

        self.assertEqual(functions[10].size,    174)
        self.assertEqual(functions[10].name,    "")

        self.assertEqual(functions[-1].address, 4409396)
        self.assertEqual(functions[-1].size,    0)
        self.assertEqual(functions[-1].name,    "_fini")


    def test_misc(self):
        sample = "ELF/ELF64_x86-64_binary_ld.bin"
        ld = lief.parse(get_sample(sample))

        text = ld.get_section(".text")

        self.assertFalse(ld.has_section_with_offset(0))
        self.assertFalse(ld.has_section_with_va(0xFFFFFFFF))

        self.assertTrue(ld.has_section_with_offset(text.offset + 10))
        self.assertTrue(ld.has_section_with_va(text.virtual_address + 10))


if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)
