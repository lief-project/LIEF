#!/usr/bin/env python
# -*- coding: utf-8 -*-

import lief
import json
from utils import get_sample

def test_basic():
    path = get_sample('PE/PE32_x86_library_kernel32.dll')
    sample = lief.parse(path)
    exports = sample.get_export()
    forwarded_exports = [exp for exp in exports.entries if exp.is_forwarded]
    assert len(forwarded_exports) == 82

    print(exports)
    print(exports.entries[0])
    print(forwarded_exports)

    # Test JSON Serialization
    json_serialized = json.loads(lief.to_json(forwarded_exports[0]))

    assert "forward_information" in json_serialized
    assert json_serialized["forward_information"]["library"] == "NTDLL"
    assert json_serialized["forward_information"]["function"] == "RtlInterlockedPushListSList"

