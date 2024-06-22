#!/usr/bin/env python
import sys
import pytest
import io
from io import open as io_open
from pathlib import Path

import lief
from utils import get_sample, is_x86_64

lief.logging.set_level(lief.logging.LEVEL.INFO)


def test_wrong_obj(capsys):
    class Empty:
        pass
    _ = lief.parse(Empty())
    captured = capsys.readouterr()
    assert "LIEF parser interface does not support Python object: test_python.Empty" in captured.err

def test_pathlib():
    lspath = Path(get_sample('ELF/ELF64_x86-64_binary_ls.bin'))
    ls = lief.parse(lspath)
    assert isinstance(ls, lief.ELF.Binary)

def test_io():
    lspath = get_sample('ELF/ELF64_x86-64_binary_ls.bin')

    ls = lief.parse(lspath)
    assert ls.abstract.header is not None

    with io_open(lspath, 'rb') as f:
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
        ls: lief.ELF.Binary  = lief.parse(f)
        assert ls.abstract.header is not None
        assert len(ls.sections) > 0

    with open(lspath, 'rb') as f:  # As io.BytesIO object
        bytes_stream = io.BytesIO(f.read())
        assert bytes_stream is not None

def test_wrong_io():
    class Wrong1:
        pass

    class Wrong2(io.IOBase):
        pass

    class Wrong3(io.IOBase):
        def tell(self):
            return 0

    class Wrong4(io.IOBase):
        def tell(self):
            return 0

        def seek(self, pos):
            return 0

    class Wrong5(io.IOBase):
        def tell(self):
            return 0

        def seek(self, p0, p1):
            return 0

        def read(self):
            return None

        def readinto(self, size):
            return None

    wrong = Wrong1()
    out = lief.parse(wrong)
    assert out is None

    wrong = Wrong2()
    out = lief.parse(wrong)
    assert out is None

    wrong = Wrong3()
    out = lief.parse(wrong)
    assert out is None

    wrong = Wrong4()
    out = lief.parse(wrong)
    assert out is None

    wrong = Wrong5()
    out = lief.parse(wrong)
    assert out is None

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


def test_hash():
    if is_x86_64():
        assert lief.hash(b"foo") == 17981288402089600942

def test_iterator():
    mfc_path = get_sample('PE/PE64_x86-64_binary_mfc-application.exe')
    mfc = lief.parse(mfc_path)
    items = mfc.resources_manager.dialogs[0].items
    assert len(items) > 0
    assert items[0] is not None

    assert next(items) is not None
    with pytest.raises(StopIteration) as e_info:
        for i in range(100):
            next(items)

    with pytest.raises(IndexError) as e_info:
           items[100]


def test_abstract_concrete():
    pe = lief.parse(get_sample('PE/PE64_x86-64_binary_HelloWorld.exe'))
    assert type(pe) == lief.PE.Binary
    abstract = pe.abstract
    assert type(abstract) == lief.Binary
    assert type(abstract.concrete) == lief.PE.Binary
