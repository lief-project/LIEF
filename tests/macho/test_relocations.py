#!/usr/bin/env python
import lief
from utils import get_sample

def test_object_relocations():
    json_api = lief.parse(get_sample('MachO/json_api.cpp_1.o'))
    assert len(json_api.sections) == 8

    assert json_api.sections[0].segment_name == "__TEXT"
    assert json_api.sections[1].segment_name == "__TEXT"
    assert json_api.sections[2].segment_name == "__TEXT"
    assert json_api.sections[3].segment_name == "__TEXT"
    assert json_api.sections[4].segment_name == "__TEXT"
    assert json_api.sections[5].segment_name == "__DATA"
    assert json_api.sections[6].segment_name == "__LD"
    assert json_api.sections[7].segment_name == "__TEXT"

    assert json_api.sections[0].name == "__text"
    assert json_api.sections[1].name == "__gcc_except_tab"
    assert json_api.sections[2].name == "__literal16"
    assert json_api.sections[3].name == "__const"
    assert json_api.sections[4].name == "__cstring"
    assert json_api.sections[5].name == "__const"
    assert json_api.sections[6].name == "__compact_unwind"
    assert json_api.sections[7].name == "__eh_frame"

    assert len(json_api.sections[0].relocations) == 381
    assert len(json_api.sections[1].relocations) == 0
    assert len(json_api.sections[2].relocations) == 0
    assert len(json_api.sections[3].relocations) == 0
    assert len(json_api.sections[4].relocations) == 0
    assert len(json_api.sections[5].relocations) == 186
    assert len(json_api.sections[6].relocations) == 186
    assert len(json_api.sections[7].relocations) == 399
