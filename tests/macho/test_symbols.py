#!/usr/bin/env python
import lief
import pathlib
import re
import sys
from utils import is_osx, get_sample, is_apple_m1

from .test_builder import run_program

def test_unexport(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_sym2remove.bin"))
    original = lief.parse(bin_path.as_posix())
    output = f"{tmp_path}/{bin_path.name}"
    exported = {s.name for s in original.symbols if s.has_export_info}

    assert "_remove_me" in exported

    original.unexport("_remove_me")

    original.write(output)
    new = lief.parse(output)

    exported = {s.name for s in new.symbols if s.has_export_info}
    assert "_remove_me" not in exported

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_osx():
        assert run_program(bin_path.as_posix())
        stdout = run_program(output)

        print(stdout)
        assert re.search(r'Hello World', stdout) is not None


def test_rm_symbols(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_sym2remove.bin"))
    original = lief.parse(bin_path.as_posix())
    output = f"{tmp_path}/{bin_path.name}"

    for s in ["__ZL6BANNER", "_remove_me"]:
        assert original.can_remove_symbol(s)
        original.remove_symbol(s)


    original.write(output)
    new = lief.parse(output)

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    assert new.get_symbol("__ZL6BANNER") is None
    assert new.get_symbol("_remove_me") is None

    if is_osx():
        assert run_program(bin_path.as_posix())
        stdout = run_program(output)

        print(stdout)
        assert re.search(r'Hello World', stdout) is not None

