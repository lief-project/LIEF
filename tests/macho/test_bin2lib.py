import ctypes
from pathlib import Path

import lief
from utils import get_sample, is_aarch64, is_osx, sign


def test_bin2lib(tmp_path: Path):
    file_path = (
        "MachO/mbedtls_selftest_arm64.bin"
        if is_aarch64()
        else "MachO/mbedtls_selftest_x86_64.bin"
    )
    bin_path = Path(get_sample(file_path))
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    original = fat.at(0)
    assert original is not None
    output = tmp_path / "libtest.dylib"

    header: lief.MachO.Header = original.header
    header.file_type = lief.MachO.Header.FILE_TYPE.DYLIB

    # Create LC_ID_DYLIB command
    original.add(lief.MachO.DylibCommand.id_dylib(str(output), 0, 1, 2))

    # Create a new export :)
    ADDR = (
        0x10000D782
        if header.cpu_type == lief.MachO.Header.CPU_TYPE.X86_64
        else 0x10004F3F4
    )
    assert original.add_exported_function(ADDR, "_lief_test_export")

    original.write(output)

    fat_new = lief.MachO.parse(output)
    assert fat_new is not None
    new = fat_new.at(0)
    assert new is not None
    checked, err = lief.MachO.check_layout(new)
    assert checked, err
    if is_osx():
        sign(output)
        lief.logging.info(f"Loading {output}")
        lib = ctypes.cdll.LoadLibrary(str(output))
        assert lib
        assert lib.lief_test_export
