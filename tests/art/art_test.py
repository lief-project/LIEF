#!/usr/bin/env python
import json
import logging
import os
import pprint
import unittest
from unittest import TestCase

import lief
from utils import get_sample

lief.logging.set_level(lief.logging.LOGGING_LEVEL.INFO)

CURRENT_DIR = os.path.abspath(os.path.dirname(__file__))

class TestART(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_art17(self):
        boot = lief.ART.parse(get_sample("ART/ART_017_AArch64_boot.art"))
        print(boot.header)
        return

    def test_art29(self):
        boot = lief.ART.parse(get_sample("ART/ART_029_ARM_boot.art"))

        print(boot.header)
        return

    def test_art30(self):
        boot = lief.ART.parse(get_sample("ART/ART_030_AArch64_boot.art"))

        print(boot.header)
        return

    def test_art44(self):
        boot = lief.ART.parse(get_sample("ART/ART_044_ARM_boot.art"))

        print(boot.header)
        return

    def test_art46(self):
        boot = lief.ART.parse(get_sample("ART/ART_046_AArch64_boot.art"))

        print(boot.header)
        return

    def test_art56(self):
        boot = lief.ART.parse(get_sample("ART/ART_056_AArch64_boot.art"))

        print(boot.header)
        return




if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)
