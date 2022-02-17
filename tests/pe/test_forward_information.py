#!/usr/bin/env python
# -*- coding: utf-8 -*-
import lief
import unittest
import logging
import json


from unittest import TestCase
from utils import get_sample

class TestForwardInfo(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.maxDiff = None

    def test_basic(self):
        path = get_sample('PE/PE32_x86_library_kernel32.dll')
        sample = lief.parse(path)
        exports = sample.get_export()
        forwarded_exports = [exp for exp in exports.entries if exp.is_forwarded]
        self.assertEqual(len(forwarded_exports), 82)
        # Test JSON Serialization
        json_serialized = json.loads(lief.to_json(forwarded_exports[0]))

        self.assertTrue("forward_information" in json_serialized)
        self.assertEqual(json_serialized["forward_information"]["library"], "NTDLL")
        self.assertEqual(json_serialized["forward_information"]["function"], "RtlInterlockedPushListSList")


if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)
