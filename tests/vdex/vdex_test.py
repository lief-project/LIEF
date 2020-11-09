#!/usr/bin/env python
import json
import logging
import os
import pprint
import unittest
from unittest import TestCase

import lief
from utils import get_sample

CURRENT_DIR = os.path.abspath(os.path.dirname(__file__))

lief.logging.set_level(lief.logging.LOGGING_LEVEL.DEBUG)

class TestVDEX(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)


    def test_vdex06(self):
        telecom = lief.VDEX.parse(get_sample('VDEX/VDEX_06_AArch64_Telecom.vdex'))

        # 1 Dex File registred
        self.assertEqual(len(telecom.dex_files), 1)

        dex_file = telecom.dex_files[0]

        dex2dex_json_info_lhs = json.loads(dex_file.dex2dex_json_info)

        json_test_path = os.path.join(CURRENT_DIR, "VDEX_06_AArch64_Telecom_quickinfo.json")
        dex2dex_json_info_rhs = None
        #self.maxDiff = None
        with open(json_test_path, 'r') as f:
            dex2dex_json_info_rhs = json.load(f)

        self.assertEqual(dex2dex_json_info_lhs, dex2dex_json_info_rhs)

    def test_vdex10(self):
        telecom = lief.VDEX.parse(get_sample('VDEX/VDEX_10_AArch64_Telecom.vdex'))

        # 1 Dex File registred
        self.assertEqual(len(telecom.dex_files), 1)

        dex_file = telecom.dex_files[0]
        dex2dex_json_info_lhs = json.loads(dex_file.dex2dex_json_info)

        json_test_path = os.path.join(CURRENT_DIR, "VDEX_10_AArch64_Telecom_quickinfo.json")

        dex2dex_json_info_rhs = None
        self.maxDiff = None

        with open(json_test_path, 'r') as f:
            dex2dex_json_info_rhs = json.load(f)
        self.assertEqual(dex2dex_json_info_lhs, dex2dex_json_info_rhs)


class TestVDEX06(TestCase):

    def test_header(self):
        telecom = lief.VDEX.parse(get_sample('VDEX/VDEX_06_AArch64_Telecom.vdex'))
        header = telecom.header

        self.assertEqual(header.magic, [118, 100, 101, 120])
        self.assertEqual(header.version, 6)
        self.assertEqual(header.nb_dex_files, 1)
        self.assertEqual(header.dex_size, 940500)
        self.assertEqual(header.quickening_info_size, 18104)
        self.assertEqual(header.verifier_deps_size, 11580)

    def test_dex_files(self):
        telecom = lief.VDEX.parse(get_sample('VDEX/VDEX_06_AArch64_Telecom.vdex'))
        h           = hash(telecom.dex_files[0])
        h_file      = lief.hash(telecom.dex_files[0].raw(False))
        h_file_dopt = lief.hash(telecom.dex_files[0].raw(True))

        #self.assertEqual(h,           8527372568967457956)
        #self.assertEqual(h_file,      18446744072392183797)
        #self.assertEqual(h_file_dopt, 18446744073629421797)


class TestVDEX10(TestCase):

    def test_header(self):
        telecom = lief.VDEX.parse(get_sample('VDEX/VDEX_10_AArch64_Telecom.vdex'))
        header = telecom.header

        self.assertEqual(header.magic, [118, 100, 101, 120])
        self.assertEqual(header.version, 10)
        self.assertEqual(header.nb_dex_files, 1)
        self.assertEqual(header.dex_size, 1421904)
        self.assertEqual(header.quickening_info_size, 584)
        self.assertEqual(header.verifier_deps_size, 18988)


    def test_dex_files(self):
        telecom = lief.VDEX.parse(get_sample('VDEX/VDEX_10_AArch64_Telecom.vdex'))
        h           = hash(telecom.dex_files[0])
        h_file      = lief.hash(telecom.dex_files[0].raw(False))
        h_file_dopt = lief.hash(telecom.dex_files[0].raw(True))

        #self.assertEqual(h,           4434625889427456908)
        #self.assertEqual(h_file,      18446744071715884987)
        #self.assertEqual(h_file_dopt, 18446744072171126186)



if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)
