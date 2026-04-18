import io
import sys
from io import open as io_open
from pathlib import Path
from typing import Any, cast

import lief
import pytest
from utils import get_sample, is_x86_64, parse_pe


def test_wrong_obj(capsys):
    class Empty:
        pass

    _ = lief.parse(cast(Any, Empty()))
    captured = capsys.readouterr()
    assert (
        "LIEF parser interface does not support this Python object: test_python.Empty"
        in captured.err
    )


def test_pathlib():
    lspath = Path(get_sample("ELF/ELF64_x86-64_binary_ls.bin"))
    ls = lief.parse(lspath)
    assert isinstance(ls, lief.ELF.Binary)


def test_io():
    lspath = get_sample("ELF/ELF64_x86-64_binary_ls.bin")

    ls = lief.parse(lspath)
    assert isinstance(ls, lief.ELF.Binary)
    assert ls.abstract.header is not None

    with io_open(lspath, "rb") as f:
        ls = lief.parse(f)
        assert isinstance(ls, lief.ELF.Binary)
        assert ls.abstract.header is not None

    with io_open(lspath, "rb") as f:
        ls = lief.parse(f)
        assert isinstance(ls, lief.ELF.Binary)
        assert ls.abstract.header is not None

    with io_open(lspath, "rb") as f:
        ls = lief.ELF.parse(f)
        assert ls is not None
        assert ls.abstract.header is not None

    with io_open(get_sample("PE/PE64_x86-64_binary_HelloWorld.exe"), "rb") as f:
        binary = lief.PE.parse(f)
        assert binary is not None
        assert binary.abstract.header is not None

    with io_open(get_sample("MachO/MachO64_x86-64_binary_dd.bin"), "rb") as f:
        fat = lief.MachO.parse(f)
        assert fat is not None
        binary = fat[0]
        assert binary is not None
        assert binary.abstract.header is not None

    with open(lspath, "rb") as f:  # As bytes
        ls = lief.parse(f.read())
        assert isinstance(ls, lief.ELF.Binary)
        assert ls.abstract.header is not None

    with open(lspath, "rb") as f:  # As io.BufferedReader
        ls = cast(lief.ELF.Binary, lief.parse(f))
        assert ls.abstract.header is not None
        assert len(ls.sections) > 0

    with open(lspath, "rb") as f:  # As io.BytesIO object
        bytes_stream = io.BytesIO(f.read())
        assert bytes_stream is not None


def test_wrong_io():
    class Wrong1:
        pass

    class Wrong2(io.IOBase):
        pass

    class Wrong3(io.IOBase):
        def tell(self):  # pragma: no cover
            return 0

    class Wrong4(io.IOBase):
        def tell(self):  # pragma: no cover
            return 0

        def seek(self, offset: int, whence: int = 0) -> int:  # pragma: no cover
            return 0

    class Wrong5(io.IOBase):
        def tell(self):
            return 0

        def seek(self, offset: int, whence: int = 0) -> int:
            return 0

        def read(self):  # pragma: no cover
            return None

        def readinto(self, size):  # pragma: no cover
            return None

    wrong = Wrong1()
    out = lief.parse(cast(Any, wrong))
    assert out is None

    wrong = Wrong2()
    out = lief.parse(cast(Any, wrong))
    assert out is None

    wrong = Wrong3()
    out = lief.parse(cast(Any, wrong))
    assert out is None

    wrong = Wrong4()
    out = lief.parse(cast(Any, wrong))
    assert out is None

    wrong = Wrong5()
    out = lief.parse(cast(Any, wrong))
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
    pe = parse_pe(
        "PE/9b58db32f6224e213cfd130d6cd7a18b2440332bfd99e0aef4313de8099fa955.neut"
    )

    mgr = pe.resources_manager
    assert isinstance(mgr, lief.PE.ResourcesManager)

    assert mgr.dialogs[0].items[0] is not None  # type: ignore

    i = mgr.dialogs[0].items  # type: ignore
    assert i[0] is not None


def test_hash():
    if is_x86_64():
        assert lief.hash(b"foo") == 17981288402089600942


def test_iterator():
    mfc_path = get_sample("PE/PE64_x86-64_binary_mfc-application.exe")
    mfc = lief.parse(mfc_path)
    assert isinstance(mfc, lief.PE.Binary)
    mgr = mfc.resources_manager
    assert isinstance(mgr, lief.PE.ResourcesManager)
    items = mgr.dialogs[0].items  # type: ignore
    assert len(items) > 0
    assert items[0] is not None

    assert next(items) is not None
    with pytest.raises(StopIteration):
        for _ in range(100):
            next(items)

    with pytest.raises(IndexError):
        items[100]


def test_abstract_concrete():
    pe = parse_pe("PE/PE64_x86-64_binary_HelloWorld.exe")
    assert type(pe) == lief.PE.Binary  # noqa
    abstract = pe.abstract
    assert type(abstract) == lief.Binary  # noqa
    assert type(abstract.concrete) == lief.PE.Binary  # noqa


def test_from_bytes():
    input_path = Path(get_sample("PE/PE64_x86-64_binary_HelloWorld.exe"))
    pe = lief.PE.parse(input_path.read_bytes())
    assert pe is not None

    input_path = Path(get_sample("ELF/python3.12d"))
    elf = lief.ELF.parse(input_path.read_bytes())
    assert elf is not None

    input_path = Path(get_sample("MachO/MachO64_AArch64_weak-sym-fc.bin"))
    macho = lief.MachO.parse(input_path.read_bytes())
    assert macho is not None
