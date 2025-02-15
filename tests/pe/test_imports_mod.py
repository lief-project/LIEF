#!python
import lief
import pytest
import ctypes

from pathlib import Path
from multiprocessing import Process

from utils import (
    get_sample, is_windows, is_x86_64, win_exec,
    has_private_samples
)
if is_windows():
    SEM_NOGPFAULTERRORBOX = 0x0002  # From MSDN
    ctypes.windll.kernel32.SetErrorMode(SEM_NOGPFAULTERRORBOX) # type: ignore

def _load_library(path: Path):
    lib = ctypes.windll.LoadLibrary(path.as_posix()) # type: ignore
    assert lib is not None

def _run_sample(input_path: Path, output: Path):
    if not is_windows() or not is_x86_64():
        return

    if input_path.name.endswith(".dll"):
        p = Process(target=_load_library, args=(output,))
        p.start()
        p.join()
        assert p.exitcode == 0

    if input_path.name == "PE64_x86-64_binary_winhello64-mingw.exe":
        ret = win_exec(output, gui=False, args=["Hello World", ])
        assert ret is not None

        retcode, stdout = ret
        assert retcode == 0
        assert len(stdout) > 0

    if input_path.name == "pe_reader.exe":
        ret = win_exec(output, gui=False, args=[output.as_posix(), ])
        assert ret is not None

        retcode, stdout = ret
        assert retcode == 0
        assert len(stdout) > 0

@pytest.mark.parametrize("sample", [
    "PE/ucrtbase.dll",   # MSVC Layout
    "PE/LIEF-win64.dll", # MSVC Layout
    "PE/PE64_x86-64_binary_winhello64-mingw.exe", # MinGW Layout
    "PE/pe_reader.exe", # MSVC Layout
    "private/PE/lief-ld-link.pyd", # LLVM LD Layout
])
def test_import_simple(tmp_path: Path, sample: str):
    """
    Test that we can relocate the import table (without relocating the IAT)
    for different layouts (link.exe, ld-link.exe, MinGW, ...)
    """

    def compare_imports(lhs: lief.PE.Binary, rhs: lief.PE.Binary) -> bool:
        imports_lhs = lhs.imports
        imports_rhs = rhs.imports
        assert len(imports_lhs) == len(imports_rhs)

        for ilhs, irhs in zip(imports_lhs, imports_rhs):
            assert ilhs.name == irhs.name
            assert ilhs.forwarder_chain == irhs.forwarder_chain
            assert ilhs.timedatestamp == irhs.timedatestamp
            assert ilhs.import_address_table_rva == irhs.import_address_table_rva
            assert ilhs.name_rva != irhs.name_rva

            assert len(ilhs.entries) == len(irhs.entries)

            for elhs, erhs in zip(ilhs.entries, irhs.entries):
                assert elhs.name == erhs.name
                assert elhs.ordinal == erhs.ordinal
                assert elhs.iat_address == erhs.iat_address
                assert elhs.iat_value == erhs.iat_value
        return True


    if sample.startswith("private/") and not has_private_samples():
        pytest.skip(reason="needs private samples")
        return

    input_path = Path(get_sample(sample))

    pe = lief.PE.parse(input_path)
    check, msg = lief.PE.check_layout(pe)
    assert check, msg

    config = lief.PE.Builder.config_t()
    config.imports = True
    config.exports = False
    config.resources = False
    config.relocations = False
    config.load_configuration = False
    config.tls = False
    config.overlay = False
    config.idata_section = ".myidata"

    output = tmp_path / input_path.name
    pe.write(output.as_posix(), config)

    new = lief.PE.parse(output)
    assert new.get_section(config.idata_section) is not None
    check, msg = lief.PE.check_layout(new)
    assert check, msg
    compare_imports(new, lief.PE.parse(input_path))

    _run_sample(input_path, output)

@pytest.mark.parametrize("sample", [
    "PE/LIEF-win64.dll", # MSVC Layout
    "PE/PE64_x86-64_binary_winhello64-mingw.exe", # MinGW Layout
    "PE/pe_reader.exe", # MSVC Layout
    "private/PE/lief-ld-link.pyd", # LLVM LD Layout
])
def test_remove_entry(tmp_path: Path, sample: str):
    """
    Make sure we can remove a function from an import while still
    being able to run the binary
    """

    if sample.startswith("private/") and not has_private_samples():
        pytest.skip(reason="needs private samples")
        return

    input_path = Path(get_sample(sample))

    pe = lief.PE.parse(input_path)

    kernel32 = pe.get_import("KERNEL32.dll")
    assert kernel32 is not None

    for imp in ("Sleep", "IsDebuggerPresent"):
        if kernel32.get_entry(imp) is not None:
            kernel32.remove_entry(imp)

    check, msg = lief.PE.check_layout(pe)
    assert check, msg

    config = lief.PE.Builder.config_t()
    config.imports = True
    config.exports = False
    config.resources = False
    config.relocations = False
    config.load_configuration = False
    config.tls = False
    config.overlay = False
    config.idata_section = ".myidata"

    output = tmp_path / input_path.name
    pe.write(output.as_posix(), config)

    new = lief.PE.parse(output)

    check, msg = lief.PE.check_layout(new)
    assert check, msg

    kernel32 = pe.get_import("KERNEL32.dll")
    assert kernel32.get_entry("Sleep") is None
    assert kernel32.get_entry("IsDebuggerPresent") is None

    _run_sample(input_path, output)

@pytest.mark.parametrize("sample", [
    "PE/LIEF-win64.dll", # MSVC Layout
    "PE/PE64_x86-64_binary_winhello64-mingw.exe", # MinGW Layout
    "PE/pe_reader.exe", # MSVC Layout
    "private/PE/lief-ld-link.pyd", # LLVM LD Layout
])
def test_rename(tmp_path: Path, sample: str):
    if sample.startswith("private/") and not has_private_samples():
        pytest.skip(reason="needs private samples")
        return

    input_path = Path(get_sample(sample))

    pe = lief.PE.parse(input_path)

    kernel32 = pe.get_import("KERNEL32.dll")
    assert kernel32 is not None

    kernel32.name = "kernel32.dll"

    check, msg = lief.PE.check_layout(pe)
    assert check, msg

    config = lief.PE.Builder.config_t()
    config.imports = True
    config.exports = False
    config.resources = False
    config.relocations = False
    config.load_configuration = False
    config.tls = False
    config.overlay = False
    config.idata_section = ".myidata"

    output = tmp_path / input_path.name
    pe.write(output.as_posix(), config)

    new = lief.PE.parse(output)

    check, msg = lief.PE.check_layout(new)
    assert check, msg

    _run_sample(input_path, output)

@pytest.mark.parametrize("sample", [
    "PE/LIEF-win64.dll", # MSVC Layout
    "PE/PE64_x86-64_binary_winhello64-mingw.exe", # MinGW Layout
    "PE/pe_reader.exe", # MSVC Layout
    "private/PE/lief-ld-link.pyd", # LLVM LD Layout
])
def test_add_import(tmp_path: Path, sample: str):
    """
    Make sure we can add a new imported library with functions
    """
    global count
    count = 0
    def on_iat_resolved(pe: lief.PE.Binary, imp: lief.PE.Import,
                        entry: lief.PE.ImportEntry, rva: int):
        global count
        count += 1
        assert imp.name == "kernel32.dll"
        assert rva > 0

    if sample.startswith("private/") and not has_private_samples():
        pytest.skip(reason="needs private samples")
        return

    input_path = Path(get_sample(sample))

    pe = lief.PE.parse(input_path)

    check, msg = lief.PE.check_layout(pe)
    assert check, msg

    new_import = pe.add_import("kernel32.dll")
    kernel32 = pe.get_import("KERNEL32.dll")
    nb_entries = len(kernel32.entries)

    for entry in kernel32.entries:
        if entry.is_ordinal:
            continue
        new_import.add_entry(entry.name)

    config = lief.PE.Builder.config_t()
    config.imports = True
    config.exports = False
    config.resources = False
    config.relocations = False
    config.load_configuration = False
    config.tls = False
    config.overlay = False
    config.resolved_iat_cbk = on_iat_resolved
    config.idata_section = ".myidata"

    output = tmp_path / input_path.name
    pe.write(output.as_posix(), config)
    assert count == nb_entries

    new = lief.PE.parse(output)

    check, msg = lief.PE.check_layout(new)
    assert check, msg
    _run_sample(input_path, output)

@pytest.mark.parametrize("sample", [
    "private/PE/lief-ld-link.pyd",
])
def test_remove_import(tmp_path: Path, sample: str):
    """
    Make sure we can strip an imported library
    """
    if sample.startswith("private/") and not has_private_samples():
        pytest.skip(reason="needs private samples")
        return

    input_path = Path(get_sample(sample))

    pe = lief.PE.parse(input_path)

    check, msg = lief.PE.check_layout(pe)
    assert check, msg

    assert pe.get_import("python311.dll") is not None

    pe.remove_import("python311.dll")

    assert pe.get_import("python311.dll") is None

    config = lief.PE.Builder.config_t()
    config.imports = True
    config.exports = False
    config.resources = False
    config.relocations = False
    config.load_configuration = False
    config.tls = False
    config.overlay = False

    config.idata_section = ".myidata"

    output = tmp_path / input_path.name
    pe.write(output.as_posix(), config)

    new = lief.PE.parse(output)

    check, msg = lief.PE.check_layout(new)
    assert check, msg
    _run_sample(input_path, output)
