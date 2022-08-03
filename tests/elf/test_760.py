#!/usr/bin/env python
import pytest

import lief
import pathlib

from utils import get_sample

def test_zero_export():
    """
    Check that LIEF does not skip an exported function
    that is located at the address 0
    """
    triton_stub = get_sample('ELF/triton-x8664-systemv-stubs.o')
    triton_stub = lief.parse(triton_stub)
    exports = {s.name for s in triton_stub.exported_functions}
    assert "memccpy" in exports

