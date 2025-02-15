#!python
import lief
import pytest
import ctypes

from pathlib import Path
from multiprocessing import Process

from utils import (
    get_sample, is_windows, is_x86_64, win_exec,
    has_private_samples, is_windows_x86_64
)

def _load_library(path: Path):
    lib = ctypes.windll.LoadLibrary(path.as_posix()) # type: ignore
    assert lib is not None

def _load_library_1(path: Path):
    lib = ctypes.windll.LoadLibrary(path.as_posix()) # type: ignore
    assert lib is not None

    assert lib.test_lief is not None
    assert getattr(lib, "foo", None) is None

def _load_library_2(path: Path):
    lib = ctypes.windll.LoadLibrary(path.as_posix()) # type: ignore
    assert lib is not None

    assert getattr(lib, "removeAppx", None) is None
    assert lib.installAppx is not None
    assert lib.checkSideloadPref is not None
    assert lib.restoreSideloadPref is not None
    assert lib.removeAppxInUserContext is not None

def _load_library_3(path: Path):
    lib = ctypes.windll.LoadLibrary(path.as_posix()) # type: ignore
    assert lib is not None

    # These calls must print 'TLS Callback #1' and 'TLS Callback #2'
    assert lib.cbk1() >= 0
    assert lib.cbk2() >= 0

def _run_sample(input_path: Path, output: Path):
    if not is_windows() or not is_x86_64():
        return

    if input_path.name.endswith(".dll"):
        p = Process(target=_load_library, args=(output,))
        p.start()
        p.join()
        assert p.exitcode == 0


    if input_path.name == "PE64_x86-64_binary_HelloWorld.exe":
        ret = win_exec(output, gui=False, args=["lief test", ])
        assert ret is not None

        retcode, stdout = ret
        assert retcode == 0
        assert len(stdout) > 0
        assert "lief test" in stdout


@pytest.mark.parametrize("sample", [
    "PE/ucrtbase.dll",   # MSVC Layout
    "PE/LIEF-win64.dll", # MSVC Layout
    "PE/PE32_x86_library_kernel32.dll", # Contains fwd exports
    "private/PE/lief-ld-link.pyd", # LLVM LD Layout

])
def test_exports_simple(tmp_path: Path, sample: str):
    """
    Test that we can relocate the export table
    for different layouts (link.exe, ld-link.exe)
    """

    def compare_exports(lhs: lief.PE.Binary, rhs: lief.PE.Binary) -> bool:
        exp_lhs = lhs.get_export()
        exp_rhs = rhs.get_export()

        assert exp_lhs.name == exp_rhs.name
        assert exp_lhs.timestamp == exp_rhs.timestamp
        assert exp_lhs.export_flags == exp_rhs.export_flags
        assert exp_lhs.major_version == exp_rhs.major_version
        assert exp_lhs.minor_version == exp_rhs.minor_version
        assert exp_lhs.ordinal_base == exp_rhs.ordinal_base
        assert exp_lhs.names_addr_table_cnt == exp_rhs.names_addr_table_cnt
        assert exp_lhs.export_addr_table_cnt == exp_rhs.export_addr_table_cnt
        assert len(exp_lhs.entries) == len(exp_rhs.entries)

        for elhs, erhs in zip(exp_lhs.entries, exp_rhs.entries):
            assert elhs.name == erhs.name
            assert elhs.forward_information.library == erhs.forward_information.library
            assert elhs.forward_information.function == erhs.forward_information.function
            assert elhs.address == erhs.address
            assert elhs.ordinal == erhs.ordinal
        return True

    if sample.startswith("private/") and not has_private_samples():
        pytest.skip(reason="needs private samples")
        return

    input_path = Path(get_sample(sample))

    pe = lief.PE.parse(input_path)
    check, msg = lief.PE.check_layout(pe)
    assert check, msg

    config = lief.PE.Builder.config_t()
    config.imports = False
    config.exports = True
    config.resources = False
    config.relocations = False
    config.load_configuration = False
    config.tls = False
    config.overlay = False
    config.debug = False
    config.export_section = ".myedata"

    output = tmp_path / input_path.name
    pe.write(output.as_posix(), config)

    new = lief.PE.parse(output)
    assert new.get_section(config.export_section) is not None
    check, msg = lief.PE.check_layout(new)
    assert check, msg
    compare_exports(new, lief.PE.parse(input_path))

    if pe.optional_header.magic == lief.PE.PE_TYPE.PE32_PLUS:
        _run_sample(input_path, output)

@pytest.mark.parametrize("sample", [
    "PE/PE64_x86-64_binary_HelloWorld.exe",
])
def test_exports_creation(tmp_path: Path, sample: str):
    """
    Make sure we can craft an export table
    """
    input_path = Path(get_sample(sample))

    pe = lief.PE.parse(input_path)
    check, msg = lief.PE.check_layout(pe)
    assert check, msg

    exp = lief.PE.Export("lief_test.dll", [
        lief.PE.ExportEntry("test_1", 0xabcd),
        lief.PE.ExportEntry("test_2", 0x1234),
    ])
    pe.set_export(exp)

    config = lief.PE.Builder.config_t()
    config.imports = False
    config.exports = True
    config.resources = False
    config.relocations = False
    config.load_configuration = False
    config.tls = False
    config.overlay = False
    config.debug = False
    config.export_section = ".myedata"

    output = tmp_path / input_path.name
    pe.write(output.as_posix(), config)

    new = lief.PE.parse(output)
    assert new.get_section(config.export_section) is not None
    check, msg = lief.PE.check_layout(new)
    assert check, msg

    new_exp = new.get_export()
    new_exp.name == "lief_test.dll"
    entries = new_exp.entries
    assert len(entries) == 2
    assert entries[0].name == "test_1"
    assert entries[0].address == 0xabcd

    assert entries[1].name == "test_2"
    assert entries[1].address == 0x1234
    _run_sample(input_path, output)

def test_add_export_entry(tmp_path: Path):
    input_path = Path(get_sample("PE/ANCUtility.dll"))

    pe = lief.PE.parse(input_path)
    check, msg = lief.PE.check_layout(pe)
    assert check, msg

    exp = pe.get_export()
    exp.add_entry("test_lief", 0x1980)

    config = lief.PE.Builder.config_t()
    config.imports = False
    config.exports = True
    config.resources = False
    config.relocations = False
    config.load_configuration = False
    config.tls = False
    config.overlay = False
    config.debug = False
    config.export_section = ".myedata"

    output = tmp_path / input_path.name
    pe.write(output.as_posix(), config)

    new = lief.PE.parse(output)
    assert new.get_section(config.export_section) is not None
    check, msg = lief.PE.check_layout(new)
    assert check, msg

    new_exp = new.get_export()
    assert new_exp.find_entry_at(0x1980).name == "test_lief"

    if is_windows_x86_64():
        p = Process(target=_load_library_1, args=(output,))
        p.start()
        p.join()
        assert p.exitcode == 0


def test_remove_entry(tmp_path: Path):
    input_path = Path(get_sample("PE/ANCUtility.dll"))

    pe = lief.PE.parse(input_path)
    check, msg = lief.PE.check_layout(pe)
    assert check, msg

    assert pe.get_export().find_entry("removeAppx") is not None
    assert pe.get_export().remove_entry("removeAppx")

    config = lief.PE.Builder.config_t()
    config.imports = False
    config.exports = True
    config.resources = False
    config.relocations = False
    config.load_configuration = False
    config.tls = False
    config.overlay = False
    config.debug = False
    config.export_section = ".myedata"

    output = tmp_path / input_path.name
    pe.write(output.as_posix(), config)

    new = lief.PE.parse(output)
    check, msg = lief.PE.check_layout(new)
    assert check, msg

    new_exp = new.get_export()
    assert new_exp.find_entry("removeAppx") is None

    if is_windows_x86_64():
        p = Process(target=_load_library_2, args=(output,))
        p.start()
        p.join()
        assert p.exitcode == 0


def test_exe2dll(tmp_path: Path):
    input_path = Path(get_sample("PE/tls_callbacks.exe"))

    pe = lief.PE.parse(input_path)
    check, msg = lief.PE.check_layout(pe)
    assert check, msg

    pe.header.add_characteristic(lief.PE.Header.CHARACTERISTICS.DLL)
    pe.optional_header.addressof_entrypoint = 0

    exp = lief.PE.Export("lib_exe2dll.dll", [
        lief.PE.ExportEntry("cbk1", 0x0001000),
        lief.PE.ExportEntry("cbk2", 0x0001010),
    ])
    pe.set_export(exp)

    config = lief.PE.Builder.config_t()
    config.imports = False
    config.exports = True
    config.resources = False
    config.relocations = False
    config.load_configuration = False
    config.tls = False
    config.overlay = False
    config.debug = False
    config.export_section = ".myedata"

    output = tmp_path / exp.name
    print(output)
    pe.write(output.as_posix(), config)

    new = lief.PE.parse(output)

    assert new.get_export().find_entry("cbk2").address == 0x0001010

    if is_windows_x86_64():
        p = Process(target=_load_library_3, args=(output,))
        p.start()
        p.join()
        assert p.exitcode == 0
