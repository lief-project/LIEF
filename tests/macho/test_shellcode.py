
#!/usr/bin/env python
import lief
import pathlib
import re
import sys
import pytest
from utils import is_osx, get_sample, is_apple_m1, is_github_ci

from test_builder import run_program

def patch(tmp_path: str, bin_path: pathlib.Path) -> str:
    original = lief.parse(bin_path.as_posix())
    shellcode_path = None

    output = f"{tmp_path}/{bin_path.name}"

    cpu = original.header.cpu_type
    if cpu == lief.MachO.CPU_TYPES.ARM64:
        shellcode_path = pathlib.Path(get_sample("MachO/shellcode-stub/lief_hello_darwin_arm64.bin"))
    elif cpu == lief.MachO.CPU_TYPES.x86_64:
        shellcode_path = pathlib.Path(get_sample("MachO/shellcode-stub/lief_hello_darwin_x86_64.bin"))
    else:
        print(f"Unsupported architecture {cpu!s} for {bin_path}")
        sys.exit(1)


    shellcode = lief.parse(shellcode_path.as_posix())

    #lief.logging.set_level(lief.logging.LOGGING_LEVEL.DEBUG)

    __TEXT  = shellcode.get_segment("__TEXT")
    __STEXT = lief.MachO.SegmentCommand("__STEXT", list(__TEXT.content))
    __STEXT = original.add(__STEXT)
    print(__STEXT)

    __STEXT.init_protection = __TEXT.init_protection
    __STEXT.max_protection  = __TEXT.max_protection

    __DATA  = shellcode.get_segment("__DATA")
    __SDATA = lief.MachO.SegmentCommand("__SDATA", list(__DATA.content))
    __SDATA = original.add(__SDATA)

    __SDATA.init_protection = __DATA.init_protection
    __SDATA.max_protection  = __DATA.max_protection

    shellcode_ep = shellcode.entrypoint - shellcode.imagebase
    new_ep = shellcode_ep + __STEXT.virtual_address - original.imagebase
    print(f"New entrypoint: 0x{new_ep:x}")

    original.main_command.entrypoint = new_ep
    print(original.main_command)

    print(f"Written in {output}")
    original.write(output)
    return output


def test_crypt_and_hash(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/9edfb04c55289c6c682a25211a4b30b927a86fe50b014610d04d6055bd4ac23d_crypt_and_hash.macho"))
    output = patch(tmp_path, bin_path)
    new = lief.parse(output)

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_apple_m1():
        stdout = run_program(output)
        print(stdout)
        assert re.search(r'LIEF says hello :\)', stdout) is not None

def test_all(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_all.bin"))
    output = patch(tmp_path, bin_path)
    new = lief.parse(output)

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_osx():
        stdout = run_program(output)
        print(stdout)
        assert re.search(r'LIEF says hello :\)', stdout) is not None

@pytest.mark.skipif(is_github_ci(), reason="sshd does not work on Github Action")
def test_ssh(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_sshd.bin"))
    output = patch(tmp_path, bin_path)
    new = lief.parse(output)

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_osx():
        stdout = run_program(output, args=["--help"])
        print(stdout)
        assert re.search(r'LIEF says hello :\)', stdout) is not None

def test_nm(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_nm.bin"))
    output = patch(tmp_path, bin_path)
    new = lief.parse(output)

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_osx():
        stdout = run_program(output)
        print(stdout)
        assert re.search(r'LIEF says hello :\)', stdout) is not None

def test_arm64_all(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_AArch64_binary_all.bin"))
    output = patch(tmp_path, bin_path)
    new = lief.parse(output)

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_apple_m1():
        stdout = run_program(output)
        print(stdout)
        assert re.search(r'LIEF says hello :\)', stdout) is not None
