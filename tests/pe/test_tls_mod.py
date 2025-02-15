#!python
import lief
import pytest
import ctypes

from pathlib import Path
from multiprocessing import Process

from utils import (
    get_sample, is_windows, is_windows_x86_64, win_exec
)
if is_windows():
    SEM_NOGPFAULTERRORBOX = 0x0002  # From MSDN
    ctypes.windll.kernel32.SetErrorMode(SEM_NOGPFAULTERRORBOX) # type: ignore

def _load_library(path: Path):
    lib = ctypes.windll.LoadLibrary(path.as_posix()) # type: ignore
    assert lib is not None

def _run_sample(input_path: Path, output: Path):
    if not is_windows_x86_64():
        return

    if input_path.name.endswith(".dll"):
        p = Process(target=_load_library, args=(output,))
        p.start()
        p.join()
        assert p.exitcode == 0

    if input_path.name == "pe_reader.exe":
        ret = win_exec(output, gui=False, args=[output.as_posix(), ])
        assert ret is not None

        retcode, stdout = ret
        assert retcode == 0
        assert len(stdout) > 0

    if input_path.name == "tls_callbacks.exe":
        ret = win_exec(output, gui=False, args=[output.as_posix(), ])
        assert ret is not None

        retcode, stdout = ret
        assert retcode == 0
        assert len(stdout) > 0

def test_remove_tls_callback(tmp_path: Path):
    input_path = Path(get_sample("PE/tls_callbacks.exe"))

    pe = lief.PE.parse(input_path)
    tls = pe.tls
    assert tls is not None

    check, msg = lief.PE.check_layout(pe)
    assert check, msg

    tls_cbk_start = tls.addressof_callbacks - pe.optional_header.imagebase
    tls_cbk_end = tls_cbk_start + len(tls.callbacks) * 8 + 4
    assert tls_cbk_start > 0

    assert len(tls.callbacks) == 1
    assert tls.callbacks[0] == 0x140001000
    tls.callbacks = []
    assert len(tls.callbacks) == 0

    output = tmp_path / input_path.name
    pe.write(output.as_posix())

    new = lief.PE.parse(output)

    check, msg = lief.PE.check_layout(new)
    assert check, msg

    assert len(new.tls.callbacks) == 0

    # Make sure the relocations are correctly removed
    for reloc in new.relocations:
        for entry in reloc.entries:
            addr = entry.address
            assert not (tls_cbk_start <= addr and addr < tls_cbk_end)

    if is_windows_x86_64():
        ret = win_exec(output, gui=False)
        assert ret is not None
        retcode, stdout = ret
        assert retcode == 0
        assert len(stdout) > 0
        assert "Hello World" in stdout
        assert "TLS Callback" not in stdout

def test_add_callback(tmp_path: Path):
    input_path = Path(get_sample("PE/tls_callbacks.exe"))
    pe = lief.PE.parse(input_path)
    tls = pe.tls
    assert tls is not None

    check, msg = lief.PE.check_layout(pe)
    assert check, msg

    new_callback_addr = 0x140001010
    callbacks = list(tls.callbacks)

    assert len(callbacks) == 1

    assert callbacks[0] == 0x140001000
    nb = 21
    for _ in range(nb):
        callbacks.append(new_callback_addr)
    tls.callbacks = callbacks

    output = tmp_path / input_path.name
    pe.write(output.as_posix())

    new = lief.PE.parse(output)

    check, msg = lief.PE.check_layout(new)
    assert check, msg

    assert len(new.tls.callbacks) == nb + 1
    assert new.tls.callbacks[0] == 0x140001000
    assert new.tls.callbacks[1] == 0x140001010
    assert new.tls.callbacks[nb] == 0x140001010

    tls = new.tls

    tls_cbk_start = tls.addressof_callbacks - pe.optional_header.imagebase
    tls_cbk_end = tls_cbk_start + len(tls.callbacks) * 8 + 4

    # Make sure we have relocation for the callback table
    found: list[lief.PE.RelocationEntry] = []
    for reloc in new.relocations:
        for entry in reloc.entries:
            addr = entry.address
            if tls_cbk_start <= addr and addr < tls_cbk_end:
                found.append(entry)
    assert len(found) == nb + 1

    if is_windows_x86_64():
        ret = win_exec(output, gui=False)
        assert ret is not None
        retcode, stdout = ret
        assert retcode == 0
        assert len(stdout) > 0
        assert "Hello World" in stdout
        assert "TLS Callback #2" in stdout

def test_remove_tls(tmp_path: Path):
    """
    Check that we can strip the whole TLS info
    """
    input_path = Path(get_sample("PE/tls_callbacks.exe"))

    pe = lief.PE.parse(input_path)
    tls = pe.tls
    assert tls is not None

    check, msg = lief.PE.check_layout(pe)
    assert check, msg

    pe.remove_tls()

    output = tmp_path / input_path.name
    pe.write(output.as_posix())

    new = lief.PE.parse(output)

    check, msg = lief.PE.check_layout(new)
    assert check, msg

    assert new.tls is None

    if is_windows_x86_64():
        ret = win_exec(output, gui=False)
        assert ret is not None
        retcode, stdout = ret
        assert retcode == 0
        assert len(stdout) > 0
        assert "Hello World" in stdout
        assert "TLS Callback" not in stdout


def test_create_tls(tmp_path: Path):
    """
    Check that we can craft custom TLS
    """
    input_path = Path(get_sample("PE/tls_callbacks.exe"))

    pe = lief.PE.parse(input_path)
    tls = pe.tls
    assert tls is not None

    check, msg = lief.PE.check_layout(pe)
    assert check, msg

    pe.remove_tls()

    empty_tls_path = tmp_path / "empty_tls.exe"
    pe.write(empty_tls_path.as_posix())

    empty_tls = lief.PE.parse(empty_tls_path)

    check, msg = lief.PE.check_layout(empty_tls)
    assert check, msg

    assert empty_tls.tls is None

    tls = lief.PE.TLS()
    tls.callbacks = [
        0x140001000,
        0x140001010,
    ]

    empty_tls.tls = tls
    output = tmp_path / "crafted_tls.exe"
    lief.logging.enable_debug()
    empty_tls.write(output.as_posix())

    new = lief.PE.parse(output)

    check, msg = lief.PE.check_layout(new)
    assert check, msg

    tls = new.tls
    assert tls is not None
    assert tls.callbacks[0] == 0x140001000
    assert tls.callbacks[1] == 0x140001010

    if is_windows_x86_64():
        ret = win_exec(output, gui=False)
        assert ret is not None
        retcode, stdout = ret
        assert retcode == 0
        assert len(stdout) > 0
        assert "Hello World" in stdout
        assert "TLS Callback #1" in stdout
        assert "TLS Callback #2" in stdout
