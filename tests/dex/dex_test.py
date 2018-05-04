#!/usr/bin/env python
import unittest
import lief
import logging
import pprint
import json
import os

from lief import Logger
Logger.set_level(lief.LOGGING_LEVEL.FATAL)
#Logger.set_level(lief.LOGGING_LEVEL.DEBUG)

from unittest import TestCase
from utils import get_sample

CURRENT_DIR = os.path.abspath(os.path.dirname(__file__))

class TestDEX(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)


class TestDEX35(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)

        self.kik_dex35 = lief.DEX.parse(get_sample("DEX/DEX35_kik.android.12.8.0.dex"))
        self.sb_dex35 = lief.DEX.parse(get_sample("DEX/DEX35_com.starbucks.mobilecard.dex"))

    def test_kik_header(self):
        header = self.kik_dex35.header

        self.assertEqual(header.magic, [100, 101, 120, 10, 48, 51, 53, 0])
        self.assertEqual(header.checksum, 0x5eabacd)
        self.assertEqual(header.signature, [222, 148, 89, 234, 112, 212, 217, 127, 146, 201, 101, 115, 66, 163, 44, 125, 125, 142, 208, 242])
        self.assertEqual(header.file_size, 0x78ac64)
        self.assertEqual(header.header_size, 0x70)
        self.assertEqual(header.endian_tag, 0x12345678)
        self.assertEqual(header.map_offset, 0x78ab88)
        self.assertEqual(header.strings, (0x70, 51568))
        self.assertEqual(header.link, (0, 0))
        self.assertEqual(header.types, (0x32630, 12530))
        self.assertEqual(header.prototypes, (0x3e9f8, 14734))
        self.assertEqual(header.fields, (0x69ca0, 33376))
        self.assertEqual(header.methods, (0xaafa0, 65254))
        self.assertEqual(header.classes, (0x12a6d0, 6893))
        self.assertEqual(header.data, (0x160470, 6465524))

    def test_kik_map(self):
        dex_map = self.kik_dex35.map
        #print(dex_map)

    def test_kik_class(self):
        classes = self.kik_dex35.classes
        self.assertEqual(len(classes), 12123)

        c0 = self.kik_dex35.get_class("android.graphics.drawable.ShapeDrawable")
        self.assertEqual(c0.pretty_name, "android.graphics.drawable.ShapeDrawable")
        self.assertEqual(len(c0.methods), 3)

        cls = self.kik_dex35.get_class("com.kik.video.mobile.KikVideoService$JoinConvoConferenceResponse$Result")
        self.assertEqual(cls.access_flags, [
            lief.DEX.ACCESS_FLAGS.PUBLIC,
            lief.DEX.ACCESS_FLAGS.FINAL,
            lief.DEX.ACCESS_FLAGS.ENUM])

        self.assertEqual(cls.source_filename, "SourceFile")
        self.assertEqual(cls.package_name, "com/kik/video/mobile")
        self.assertEqual(cls.name, "KikVideoService$JoinConvoConferenceResponse$Result")
        self.assertEqual(cls.parent.pretty_name, "java.lang.Enum")
        self.assertEqual(len(cls.methods), 14)
        self.assertEqual(cls.index, 6220)

        methods_name = set(m.name for m in cls.methods)
        self.assertEqual(methods_name, set([
            '<clinit>', '<init>', 'forNumber', 'getDescriptor',
            'internalGetValueMap', 'valueOf', 'valueOf',
            'valueOf', 'values', 'getDescriptorForType',
            'getNumber', 'getValueDescriptor',
            'clone', 'ordinal']))


    def test_kik_methods(self):
        methods = self.kik_dex35.methods

        self.assertEqual(len(methods), 65254)

        ValueAnimator = self.kik_dex35.get_class("android.animation.ValueAnimator")
        m0 = ValueAnimator.get_method("setRepeatMode")[0]

        self.assertEqual(m0.name,            "setRepeatMode")
        self.assertEqual(m0.cls.pretty_name, "android.animation.ValueAnimator")
        self.assertEqual(m0.code_offset,     0)
        self.assertEqual(m0.bytecode,        [])
        self.assertEqual(m0.index,           100)
        #self.assertEqual(m0.is_virtual,      False) # TODO
        self.assertEqual(m0.prototype.return_type.value, lief.DEX.Type.PRIMITIVES.VOID_T)
        self.assertEqual(m0.access_flags, [])





class TestDEX37(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)

class TestDEX38(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)
        #self.dex38 = lief.DEX.parse(get_sample("DEX/DEX38-Framework.dex"))
        #self.dex38 = lief.DEX.parse("/home/romain/dev/LIEF/_work/dex/ArrayClass.dex")

    def test_header(self):
        #print(self.dex38.header)
        pass




if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)

