import lief
import pathlib
import ctypes

from utils import is_osx, get_sample, is_aarch64, sign

def test_bin2lib(tmp_path):
    file_path = "MachO/mbedtls_selftest_arm64.bin" if is_aarch64() else "MachO/mbedtls_selftest_x86_64.bin"
    bin_path = pathlib.Path(get_sample(file_path))
    original = lief.MachO.parse(bin_path.as_posix()).at(0)
    output = f"{tmp_path}/libtest.dylib"

    header: lief.MachO.Header = original.header
    header.file_type = lief.MachO.Header.FILE_TYPE.DYLIB

    # Create LC_ID_DYLIB command
    original.add(lief.MachO.DylibCommand.id_dylib(output, 0, 1, 2))

    # Create a new export :)
    ADDR = 0x10000D782 if header.cpu_type == lief.MachO.Header.CPU_TYPE.X86_64 else 0x10004F3F4
    assert original.add_exported_function(ADDR, "_lief_test_export")

    original.write(output)

    new = lief.MachO.parse(output).at(0)
    checked, err = lief.MachO.check_layout(new)
    assert checked, err
    if is_osx():
        sign(output)
        print(f"Loading {output}")
        lib = ctypes.cdll.LoadLibrary(output)
        assert lib
        assert lib.lief_test_export
