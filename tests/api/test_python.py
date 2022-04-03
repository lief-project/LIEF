#!/usr/bin/env python
import sys
import io
from io import open as io_open

import lief
from utils import get_sample

lief.logging.set_level(lief.logging.LOGGING_LEVEL.INFO)

def test_io():
    lspath = get_sample('ELF/ELF64_x86-64_binary_ls.bin')

    ls = lief.parse(lspath)
    assert ls.abstract.header is not None

    with io_open(lspath, 'r') as f:
        ls = lief.parse(f)
        assert ls.abstract.header is not None

    with io_open(lspath, 'rb') as f:
        ls = lief.parse(f)
        assert ls.abstract.header is not None

    with io_open(lspath, 'rb') as f:
        ls = lief.ELF.parse(f)
        assert ls.abstract.header is not None

    with io_open(get_sample('PE/PE64_x86-64_binary_HelloWorld.exe'), 'rb') as f:
        binary = lief.PE.parse(f)
        assert binary.abstract.header is not None

    with io_open(get_sample('MachO/MachO64_x86-64_binary_dd.bin'), 'rb') as f:
        binary = lief.MachO.parse(f)[0]
        assert binary.abstract.header is not None

    with open(lspath, 'rb') as f:  # As bytes
        ls = lief.parse(f.read())
        assert ls.abstract.header is not None

    with open(lspath, 'rb') as f:  # As io.BufferedReader
        ls = lief.parse(f)
        assert ls.abstract.header is not None

    with open(lspath, 'rb') as f:  # As io.BytesIO object
        bytes_stream = io.BytesIO(f.read())
        assert bytes_stream is not None

def test_platform():
    if sys.platform.lower().startswith("linux"):
        assert lief.current_platform() == lief.PLATFORMS.LINUX

    if sys.platform.lower().startswith("darwin"):
        assert lief.current_platform() == lief.PLATFORMS.OSX

    if sys.platform.lower().startswith("win"):
        assert lief.current_platform() == lief.PLATFORMS.WINDOWS

def test_issue_688():
    """
    https://github.com/lief-project/LIEF/issues/688
    """
    pe = lief.parse(get_sample("PE/9b58db32f6224e213cfd130d6cd7a18b2440332bfd99e0aef4313de8099fa955.neut"))

    assert pe.resources_manager.dialogs[0].items[0] is not None

    i = pe.resources_manager.dialogs[0].items
    assert i[0] is not None
