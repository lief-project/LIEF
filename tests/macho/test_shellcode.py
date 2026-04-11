import re
from pathlib import Path
from typing import cast

import lief
import pytest
from utils import get_sample, is_apple_m1, is_github_ci, is_osx

from .test_builder import run_program


def patch(tmp_path: Path, bin_path: Path) -> Path:
    original = lief.MachO.parse(bin_path)
    assert original is not None
    target = original.at(0)
    assert target is not None

    output = tmp_path / bin_path.name

    cpu = target.header.cpu_type
    if cpu == lief.MachO.Header.CPU_TYPE.ARM64:
        shellcode_path = Path(
            get_sample("MachO/shellcode-stub/lief_hello_darwin_arm64.bin")
        )
    elif cpu == lief.MachO.Header.CPU_TYPE.X86_64:
        shellcode_path = Path(
            get_sample("MachO/shellcode-stub/lief_hello_darwin_x86_64.bin")
        )
    else:
        raise RuntimeError(f"Unsupported architecture {cpu} for {bin_path}")

    shellcode_fat = lief.MachO.parse(shellcode_path)
    assert shellcode_fat is not None
    shellcode = shellcode_fat.at(0)
    assert shellcode is not None

    __TEXT = shellcode.get_segment("__TEXT")
    assert __TEXT is not None
    __STEXT = lief.MachO.SegmentCommand("__STEXT", list(__TEXT.content))
    __STEXT_added = cast(lief.MachO.SegmentCommand, target.add(__STEXT))

    __STEXT_added.init_protection = __TEXT.init_protection
    __STEXT_added.max_protection = __TEXT.max_protection

    __DATA = shellcode.get_segment("__DATA")
    assert __DATA is not None
    __SDATA = lief.MachO.SegmentCommand("__SDATA", list(__DATA.content))
    __SDATA_added = cast(lief.MachO.SegmentCommand, target.add(__SDATA))

    __SDATA_added.init_protection = __DATA.init_protection
    __SDATA_added.max_protection = __DATA.max_protection

    shellcode_ep = shellcode.entrypoint - shellcode.imagebase
    new_ep = shellcode_ep + __STEXT_added.virtual_address - target.imagebase

    main_cmd = target.main_command
    assert main_cmd is not None
    main_cmd.entrypoint = new_ep

    target.write(output)
    return output


def test_crypt_and_hash(tmp_path: Path):
    bin_path = Path(
        get_sample(
            "MachO/9edfb04c55289c6c682a25211a4b30b927a86fe50b014610d04d6055bd4ac23d_crypt_and_hash.macho"
        )
    )
    output = patch(tmp_path, bin_path)
    new = lief.MachO.parse(output)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_apple_m1():
        stdout = run_program(output)
        lief.logging.info(stdout)
        assert re.search(r"LIEF says hello :\)", stdout) is not None


def test_all(tmp_path: Path):
    bin_path = Path(get_sample("MachO/MachO64_x86-64_binary_all.bin"))
    output = patch(tmp_path, bin_path)
    new = lief.MachO.parse(output)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_osx():
        stdout = run_program(output)
        lief.logging.info(stdout)
        assert re.search(r"LIEF says hello :\)", stdout) is not None


@pytest.mark.skipif(is_github_ci(), reason="sshd does not work on Github Action")
def test_ssh(tmp_path: Path):
    bin_path = Path(get_sample("MachO/MachO64_x86-64_binary_sshd.bin"))
    output = patch(tmp_path, bin_path)
    new = lief.MachO.parse(output)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_osx():
        stdout = run_program(output, args=["--help"])
        lief.logging.info(stdout)
        assert re.search(r"LIEF says hello :\)", stdout) is not None


def test_nm(tmp_path: Path):
    bin_path = Path(get_sample("MachO/MachO64_x86-64_binary_nm.bin"))
    output = patch(tmp_path, bin_path)
    new = lief.MachO.parse(output)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_osx():
        stdout = run_program(output)
        lief.logging.info(stdout)
        assert re.search(r"LIEF says hello :\)", stdout) is not None


def test_arm64_all(tmp_path: Path):
    bin_path = Path(get_sample("MachO/MachO64_AArch64_binary_all.bin"))
    output = patch(tmp_path, bin_path)
    new = lief.MachO.parse(output)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_apple_m1():
        stdout = run_program(output)
        lief.logging.info(stdout)
        assert re.search(r"LIEF says hello :\)", stdout) is not None
