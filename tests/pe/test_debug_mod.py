import ctypes
from functools import lru_cache
from multiprocessing import Process
from pathlib import Path

import lief
import pytest
from utils import get_sample, is_windows_x86_64

_DEFAULT_NEW_SEC = ".ldbg"


@lru_cache(maxsize=1)
def _get_default_config() -> lief.PE.Builder.config_t:
    conf = lief.PE.Builder.config_t()
    conf.debug = True
    conf.debug_section = _DEFAULT_NEW_SEC
    return conf


def _load_library(path: Path):
    lib = ctypes.windll.LoadLibrary(path.as_posix())  # type: ignore
    assert lib is not None


def _run_sample(input_path: Path, output: Path):
    if not is_windows_x86_64():
        return

    if input_path.name.endswith(".dll"):
        p = Process(target=_load_library, args=(output,))
        p.start()
        p.join()
        assert p.exitcode == 0


def _compare_dbg(pe_lhs: lief.PE.Binary, pe_rhs: lief.PE.Binary):
    assert len(pe_lhs.debug) == len(pe_rhs.debug)

    for lhs, rhs in zip(pe_lhs.debug, pe_rhs.debug):
        assert lhs.type == rhs.type
        assert lhs.characteristics == rhs.characteristics
        assert lhs.timestamp == rhs.timestamp
        assert lhs.major_version == rhs.major_version
        assert lhs.minor_version == rhs.minor_version
        assert lhs.payload == rhs.payload
        assert lhs.addressof_rawdata == rhs.addressof_rawdata
        assert lhs.pointerto_rawdata == rhs.pointerto_rawdata


@pytest.mark.parametrize(
    "sample",
    [
        "PE/PE32_x86_binary_PGO-LTCG.exe",
        "PE/PE32_x86_binary_PGO-PGI.exe",
        "PE/PE64_x86-64_binary_ConsoleApplication1.exe",
        "PE/ntoskrnl.exe",
        "PE/LIEF-win64.dll",
        "PE/ANCUtility.dll",
    ],
)
def test_dbg_mod_idempotency(tmp_path: Path, sample: str):
    input_path = Path(get_sample(sample))
    pe = lief.PE.parse(input_path)
    assert pe is not None

    output = tmp_path / input_path.name
    pe.write(output, _get_default_config())

    new = lief.PE.parse(output)
    assert new is not None
    check, msg = lief.PE.check_layout(new)
    assert check, msg

    pe = lief.PE.parse(input_path)
    assert pe is not None

    # Make sure that we don't relocate the debug headers without modifications
    pe_debug_dir = pe.debug_dir
    assert pe_debug_dir is not None
    new_debug_dir = new.debug_dir
    assert new_debug_dir is not None
    assert pe_debug_dir.rva == new_debug_dir.rva

    _compare_dbg(new, pe)


def test_dbg_modify_entry(tmp_path: Path):
    input_path = Path(get_sample("PE/ANCUtility.dll"))
    pe = lief.PE.parse(input_path)
    assert pe is not None

    cv_pdb = pe.codeview_pdb
    assert cv_pdb is not None

    cv_pdb.filename = r"C:\lief_test.pdb"
    cv_pdb.age = 3

    output = tmp_path / input_path.name
    pe.write(output, _get_default_config())
    new = lief.PE.parse(output)
    assert new is not None
    check, msg = lief.PE.check_layout(new)

    assert check, msg
    new_cv_pdb = new.codeview_pdb
    assert new_cv_pdb is not None
    assert new_cv_pdb.filename == r"C:\lief_test.pdb"
    assert new_cv_pdb.age == 3

    # Make sure we didn't relocate the payload
    assert new_cv_pdb.addressof_rawdata == cv_pdb.addressof_rawdata
    _run_sample(input_path, output)

    pe = lief.PE.parse(input_path)
    assert pe is not None

    cv_pdb = pe.codeview_pdb
    assert cv_pdb is not None

    cv_pdb.filename = r"D:\Build\Target\Acrobat\Installers\ANCUtility\Release_x64\ANCUtility_debug.pdb"
    cv_pdb.age = 3

    output = tmp_path / input_path.name
    pe.write(output, _get_default_config())
    new = lief.PE.parse(output)
    assert new is not None
    check, msg = lief.PE.check_layout(new)
    assert check, msg

    new_cv_pdb = new.codeview_pdb
    assert new_cv_pdb is not None
    assert (
        new_cv_pdb.filename
        == r"D:\Build\Target\Acrobat\Installers\ANCUtility\Release_x64\ANCUtility_debug.pdb"
    )
    assert new_cv_pdb.age == 3
    assert new_cv_pdb.addressof_rawdata != cv_pdb.addressof_rawdata
    _run_sample(input_path, output)


def test_dbg_delete_add(tmp_path: Path):
    input_path = Path(get_sample("PE/ANCUtility.dll"))
    pe = lief.PE.parse(input_path)
    assert pe is not None
    cv_pdb = pe.codeview_pdb
    assert cv_pdb is not None
    pe.remove_debug(cv_pdb)
    pe_debug_dir = pe.debug_dir
    assert pe_debug_dir is not None
    debug_dir_rva = pe_debug_dir.rva

    assert pe.codeview_pdb is None

    output = tmp_path / input_path.name
    pe.write(output, _get_default_config())

    new = lief.PE.parse(output)
    assert new is not None
    assert new.codeview_pdb is None

    # Make sure we didn't relocate the header
    new_debug_dir = new.debug_dir
    assert new_debug_dir is not None
    assert new_debug_dir.rva == debug_dir_rva

    new_cv = lief.PE.CodeViewPDB(r"C:\Some\random\Path\to\the\pdb\target.pdb")
    new_cv.age = 33
    assert new_cv.signature == [0] * 16

    new_cv.signature = list(b"HelloWorld\0\0\0\0\0\0")

    new.add_debug_info(new_cv)

    assert new.codeview_pdb is not None
    assert new.codeview_pdb.filename == r"C:\Some\random\Path\to\the\pdb\target.pdb"
    assert new.codeview_pdb.age == 33

    output = tmp_path / f"bis_{input_path.name}"
    new.write(output, _get_default_config())

    new = lief.PE.parse(output)
    assert new is not None

    new_cv_pdb = new.codeview_pdb
    assert new_cv_pdb is not None
    assert new_cv_pdb.filename == r"C:\Some\random\Path\to\the\pdb\target.pdb"
    assert new_cv_pdb.age == 33
    assert new_cv_pdb.guid == "6c6c6548-576f-726f-6c64-000000000000"
    assert bytes(new_cv_pdb.signature) == b"HelloWorld\0\0\0\0\0\0"

    assert new.get_section(_DEFAULT_NEW_SEC) is not None

    _run_sample(input_path, output)


def test_clear_debug(tmp_path: Path):
    input_path = Path(get_sample("PE/ANCUtility.dll"))
    pe = lief.PE.parse(input_path)
    assert pe is not None
    pe.clear_debug()

    output = tmp_path / input_path.name
    pe.write(output, _get_default_config())

    delta = output.stat().st_size - input_path.stat().st_size
    assert delta <= 0

    new = lief.PE.parse(output)
    assert new is not None
    assert not new.has_debug

    _run_sample(input_path, output)
