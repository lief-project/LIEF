#!/usr/bin/env python
import lief
import tempfile
import subprocess
import pathlib
import re
import pytest
from subprocess import Popen
from utils import is_osx, get_sample, is_apple_m1

from .test_builder import run_program

LIBRARY_CODE = r"""\
#include <stdio.h>
#include <stdlib.h>

__attribute__((constructor))
void my_constructor(void) {
  printf("CTOR CALLED\n");
}
"""

def compile(output, extra_flags=None):
    if not is_osx():
        return

    extra_flags = extra_flags if extra_flags else []
    with tempfile.NamedTemporaryFile(prefix="libexample_", suffix=".c", delete=False) as ftmp:
        with open(ftmp.name, 'w') as f:
            f.write(LIBRARY_CODE)

    COMPILER = "/usr/bin/clang"
    CC_FLAGS = ['-fPIC', '-shared']
    extra_flags = [] if extra_flags is None else extra_flags
    cmd = [COMPILER] + extra_flags + CC_FLAGS + ['-o', output] + [ftmp.name]
    print("Compile 'libexample' with: {}".format(" ".join(cmd)))

    with Popen(cmd, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
        output = proc.stdout.read()
        print(output)
        return output
    return None

@pytest.mark.skipif(not is_osx(), reason="requires OSX")
def test_ssh(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_sshd.bin"))
    original = lief.MachO.parse(bin_path.as_posix()).at(0)
    output = f"{tmp_path}/sshd_injected.bin"
    library_path = f"{tmp_path}/libexample.dylib"
    compile(library_path, extra_flags=["-arch", "x86_64"])

    original.add_library(library_path)

    original.remove_signature()
    original.write(output)
    new = lief.MachO.parse(output).at(0)

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    stdout = run_program(output, ["--help"])
    print(stdout)

    assert re.search(r'CTOR CALLED', stdout) is not None

@pytest.mark.skipif(not is_apple_m1(), reason="requires Apple M1")
def test_crypt_and_hash(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/9edfb04c55289c6c682a25211a4b30b927a86fe50b014610d04d6055bd4ac23d_crypt_and_hash.macho"))
    original = lief.MachO.parse(bin_path.as_posix()).at(0)
    output = f"{tmp_path}/crypt_and_hash.bin"
    library_path = f"{tmp_path}/libexample.dylib"
    compile(library_path, extra_flags=["-arch", "arm64"])

    original.add_library(library_path)

    original.remove_signature()
    original.write(output)
    new = lief.MachO.parse(output).at(0)

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    stdout = run_program(output)
    print(stdout)

    assert re.search(r'CTOR CALLED', stdout) is not None

@pytest.mark.skipif(not is_apple_m1(), reason="requires Apple M1")
def test_all_arm64(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_AArch64_binary_all.bin"))
    original = lief.parse(bin_path.as_posix())
    output = f"{tmp_path}/all.bin"
    library_path = f"{tmp_path}/libexample.dylib"
    compile(library_path, extra_flags=["-arch", "arm64"])

    original.add_library(library_path)

    original.remove_signature()
    original.write(output)
    new = lief.parse(output)

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    stdout = run_program(output)
    print(stdout)

    assert re.search(r'CTOR CALLED', stdout) is not None

@pytest.mark.skipif(not is_osx(), reason="requires OSX")
def test_all_x86_64(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_all.bin"))
    original = lief.parse(bin_path.as_posix())
    output = f"{tmp_path}/all.bin"
    library_path = f"{tmp_path}/libexample.dylib"
    compile(library_path, extra_flags=["-arch", "x86_64"])

    original.add_library(library_path)

    original.remove_signature()
    original.write(output)
    new = lief.parse(output)

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    stdout = run_program(output)
    print(stdout)

    assert re.search(r'CTOR CALLED', stdout) is not None
