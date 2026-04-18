import pathlib
import re
import subprocess
import tempfile
from pathlib import Path
from subprocess import Popen

import lief
import pytest
from utils import get_sample, is_apple_m1, is_osx

from .test_builder import run_program

LIBRARY_CODE = r"""\
#include <stdio.h>
#include <stdlib.h>

__attribute__((constructor))
void my_constructor(void) {
  printf("CTOR CALLED\n");
}
"""


def compile(output: Path, extra_flags: list[str] | None = None) -> str:
    extra_flags = extra_flags if extra_flags else []
    with tempfile.NamedTemporaryFile(
        prefix="libexample_", suffix=".c", delete=False
    ) as ftmp:
        with open(ftmp.name, "w") as f:
            f.write(LIBRARY_CODE)

    COMPILER = "/usr/bin/clang"
    CC_FLAGS = ["-fPIC", "-shared"]
    extra_flags = [] if extra_flags is None else extra_flags
    cmd = [COMPILER] + extra_flags + CC_FLAGS + ["-o", str(output)] + [ftmp.name]
    lief.logging.info("Compile 'libexample' with: {}".format(" ".join(cmd)))

    with Popen(
        cmd, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    ) as proc:
        assert proc.stdout is not None
        stdout = proc.stdout.read()
        lief.logging.info(stdout)
        return stdout


@pytest.mark.skipif(not is_osx(), reason="requires OSX")
def test_ssh(tmp_path: Path):
    bin_path = Path(get_sample("MachO/MachO64_x86-64_binary_sshd.bin"))
    fat_parsed = lief.MachO.parse(bin_path)
    assert fat_parsed is not None
    original = fat_parsed.at(0)
    assert original is not None
    output = tmp_path / "sshd_injected.bin"
    library_path = tmp_path / "libexample.dylib"
    compile(library_path, extra_flags=["-arch", "x86_64"])

    original.add_library(str(library_path))

    original.remove_signature()
    original.write(output)
    fat_new = lief.MachO.parse(output)
    assert fat_new is not None
    new = fat_new.at(0)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    stdout = run_program(output, ["--help"])
    lief.logging.info(stdout)

    assert re.search(r"CTOR CALLED", stdout) is not None


@pytest.mark.skipif(not is_apple_m1(), reason="requires Apple M1")
def test_crypt_and_hash(tmp_path: Path):
    bin_path = pathlib.Path(
        get_sample(
            "MachO/9edfb04c55289c6c682a25211a4b30b927a86fe50b014610d04d6055bd4ac23d_crypt_and_hash.macho"
        )
    )
    fat_parsed = lief.MachO.parse(bin_path)
    assert fat_parsed is not None
    original = fat_parsed.at(0)
    assert original is not None
    output = tmp_path / "crypt_and_hash.bin"
    library_path = tmp_path / "libexample.dylib"
    compile(library_path, extra_flags=["-arch", "arm64"])

    original.add_library(str(library_path))

    original.remove_signature()
    original.write(output)
    fat_new = lief.MachO.parse(output)
    assert fat_new is not None
    new = fat_new.at(0)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    stdout = run_program(pathlib.Path(output))
    lief.logging.info(stdout)

    assert re.search(r"CTOR CALLED", stdout) is not None


@pytest.mark.skipif(not is_apple_m1(), reason="requires Apple M1")
def test_all_arm64(tmp_path: Path):
    bin_path = Path(get_sample("MachO/MachO64_AArch64_binary_all.bin"))
    fat_parsed = lief.MachO.parse(bin_path)
    assert fat_parsed is not None
    original = fat_parsed.at(0)
    assert original is not None
    output = tmp_path / "all.bin"
    library_path = tmp_path / "libexample.dylib"
    compile(library_path, extra_flags=["-arch", "arm64"])

    original.add_library(str(library_path))

    original.remove_signature()
    original.write(output)
    new = lief.MachO.parse(output)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    stdout = run_program(pathlib.Path(output))
    lief.logging.info(stdout)

    assert re.search(r"CTOR CALLED", stdout) is not None


@pytest.mark.skipif(not is_osx(), reason="requires OSX")
def test_all_x86_64(tmp_path: Path):
    bin_path = Path(get_sample("MachO/MachO64_x86-64_binary_all.bin"))
    fat_parsed = lief.MachO.parse(bin_path)
    assert fat_parsed is not None
    original = fat_parsed.at(0)
    assert original is not None
    output = tmp_path / "all.bin"
    library_path = tmp_path / "libexample.dylib"
    compile(library_path, extra_flags=["-arch", "x86_64"])

    original.add_library(str(library_path))

    original.remove_signature()
    original.write(output)
    new = lief.MachO.parse(output)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    stdout = run_program(pathlib.Path(output))
    lief.logging.info(stdout)

    assert re.search(r"CTOR CALLED", stdout) is not None


@pytest.mark.parametrize(
    "sample",
    [
        "MachO/MachO64_x86-64_binary_sshd.bin",
        "MachO/issue_1130.macho",
    ],
)
def test_segment_caching(tmp_path: Path, sample):
    bin_path = Path(get_sample(sample))
    fat_parsed = lief.MachO.parse(bin_path)
    assert fat_parsed is not None
    original = fat_parsed.at(0)
    assert original is not None
    output = tmp_path / bin_path.name
    library_path = "/private/var/folders/vb/jj4r3nc1657b19v26p3kpclc0000gp/T/pytest-of-github-runner/pytest-18/test_ssh0/libexample.dylib"

    original.add_library(str(library_path))

    original.remove_signature()
    original.write(output)
    fat_new = lief.MachO.parse(output)
    assert fat_new is not None
    new = fat_new.at(0)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err
