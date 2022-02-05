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


    def test_kik_fields(self):
        fields = self.kik_dex35.fields

        self.assertEqual(len(fields), 33376)

        Result = self.kik_dex35.get_class("com.kik.video.mobile.KikVideoService$JoinConvoConferenceResponse$Result")
        if0 = Result.get_field("value")[0]
        sf0 = Result.get_field("FULL")[0]

        self.assertEqual(if0.name,                  "value")
        self.assertEqual(if0.cls.pretty_name,       "com.kik.video.mobile.KikVideoService$JoinConvoConferenceResponse$Result")
        self.assertEqual(if0.type.value,            lief.DEX.Type.PRIMITIVES.INT)
        self.assertEqual(if0.is_static,             False)
        self.assertEqual(if0.access_flags,          [
            lief.DEX.ACCESS_FLAGS.PRIVATE,
            lief.DEX.ACCESS_FLAGS.FINAL])

        self.assertEqual(sf0.name,                  "FULL")
        self.assertEqual(sf0.cls.pretty_name,       "com.kik.video.mobile.KikVideoService$JoinConvoConferenceResponse$Result")
        self.assertEqual(sf0.type.value.pretty_name,"com.kik.video.mobile.KikVideoService$JoinConvoConferenceResponse$Result")
        self.assertEqual(sf0.is_static,             True)
        self.assertEqual(sf0.access_flags,          [
            lief.DEX.ACCESS_FLAGS.PUBLIC,
            lief.DEX.ACCESS_FLAGS.STATIC,
            lief.DEX.ACCESS_FLAGS.FINAL,
            lief.DEX.ACCESS_FLAGS.ENUM])

    def test_kik_iterators(self):
        ValueAnimator = self.kik_dex35.get_class("android.animation.ValueAnimator")
        self.assertEqual(len(list(ValueAnimator.get_method("test"))), 0)
        self.assertEqual(len(list(ValueAnimator.get_method("setValues"))), 1)





class TestDEX37(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)

class TestDEX38(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)
        #self.dex38 = lief.DEX.parse(get_sample("DEX/DEX38-Framework.dex"))

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
