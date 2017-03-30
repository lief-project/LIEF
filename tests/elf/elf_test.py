#!/usr/bin/env python
import unittest
import lief

from unittest import TestCase
from utils import get_sample

class TestELF(TestCase):

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









if __name__ == '__main__':
    unittest.main(verbosity = 2)

