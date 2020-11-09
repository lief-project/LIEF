#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import os
import random
import sys
import unittest
from unittest import TestCase

import lief
from utils import get_sample

lief.logging.set_level(lief.logging.LOGGING_LEVEL.INFO)

class TestLoadConfig(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)


    def test_winapp(self):
        winapp = lief.parse(get_sample('PE/PE64_x86-64_binary_WinApp.exe'))
        self.assertTrue(winapp.has_configuration)

        lconf = winapp.load_configuration

        self.assertEqual(lconf.version, lief.PE.WIN_VERSION.WIN10_0_15002)
        self.assertEqual(lconf.characteristics, 0xF8)
        self.assertEqual(lconf.timedatestamp, 0)
        self.assertEqual(lconf.major_version, 0)
        self.assertEqual(lconf.minor_version, 0)
        self.assertEqual(lconf.global_flags_clear, 0)
        self.assertEqual(lconf.global_flags_set, 0)
        self.assertEqual(lconf.critical_section_default_timeout, 0)
        self.assertEqual(lconf.decommit_free_block_threshold, 0)
        self.assertEqual(lconf.decommit_total_free_threshold, 0)
        self.assertEqual(lconf.lock_prefix_table, 0)
        self.assertEqual(lconf.maximum_allocation_size, 0)
        self.assertEqual(lconf.virtual_memory_threshold, 0)
        self.assertEqual(lconf.process_affinity_mask, 0)
        self.assertEqual(lconf.process_heap_flags, 0)
        self.assertEqual(lconf.csd_version, 0)
        self.assertEqual(lconf.reserved1, 0)
        self.assertEqual(lconf.editlist, 0)
        self.assertEqual(lconf.security_cookie, 0x4000d008)

        # V0
        self.assertEqual(lconf.se_handler_table, 0)
        self.assertEqual(lconf.se_handler_count, 0)

        # V1
        self.assertEqual(lconf.guard_cf_check_function_pointer, 0x140012000)
        self.assertEqual(lconf.guard_cf_dispatch_function_pointer, 0x140012010)
        self.assertEqual(lconf.guard_cf_function_table, 0x140011000)
        self.assertEqual(lconf.guard_cf_function_count, 15)

        expected_flags  = lief.PE.GUARD_CF_FLAGS.GCF_LONGJUMP_TABLE_PRESENT
        expected_flags |= lief.PE.GUARD_CF_FLAGS.GCF_FUNCTION_TABLE_PRESENT
        expected_flags |= lief.PE.GUARD_CF_FLAGS.GCF_INSTRUMENTED
        self.assertEqual(lconf.guard_flags, lief.PE.GUARD_CF_FLAGS(expected_flags))

        # V2
        code_integrity = lconf.code_integrity

        self.assertEqual(code_integrity.flags, 0)
        self.assertEqual(code_integrity.catalog, 0)
        self.assertEqual(code_integrity.catalog_offset, 0)
        self.assertEqual(code_integrity.reserved, 0)

        # V3
        self.assertEqual(lconf.guard_address_taken_iat_entry_table, 0)
        self.assertEqual(lconf.guard_address_taken_iat_entry_count, 0)
        self.assertEqual(lconf.guard_long_jump_target_table, 0)
        self.assertEqual(lconf.guard_long_jump_target_count, 0)

        # V4
        self.assertEqual(lconf.dynamic_value_reloc_table, 0)
        self.assertEqual(lconf.hybrid_metadata_pointer, 0)

        # V5
        self.assertEqual(lconf.guard_rf_failure_routine, 0x140001040)
        self.assertEqual(lconf.guard_rf_failure_routine_function_pointer, 0x140012020)
        self.assertEqual(lconf.dynamic_value_reloctable_offset, 0)
        self.assertEqual(lconf.dynamic_value_reloctable_section, 0)
        self.assertEqual(lconf.reserved2, 0)

        # V6
        self.assertEqual(lconf.guard_rf_verify_stackpointer_function_pointer, 0x140012030)
        self.assertEqual(lconf.hotpatch_table_offset, 0)



if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)
