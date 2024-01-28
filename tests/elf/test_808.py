#!/usr/bin/env python
import lief

from utils import get_sample

def test_core_offset_0():
    file = get_sample('ELF/ELF_Core_issue_808.core')
    core = lief.ELF.parse(file)
    assert len(core.notes) == 7

