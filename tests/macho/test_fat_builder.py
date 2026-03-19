#!/usr/bin/env python
import re
import pathlib
import lief
from utils import get_sample, is_osx
from .test_builder import run_program

def test_all(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/FAT_MachO_x86-x86-64-binary_fatall.bin"))
    original = lief.MachO.parse(bin_path)
    output = f"{tmp_path}/{bin_path.name}"

    assert len(original) == 2
    original.write(output)

    new = lief.MachO.parse(output)

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_osx():
        stdout = run_program(output)
        lief.logging.info(stdout)
        assert re.search(r'Hello World', stdout) is not None

def test_create_fat():
    fat = lief.MachO.FatBinary.create([
        lief.MachO.parse(get_sample("MachO/variants_alt.dylib")).take(lief.MachO.Header.CPU_TYPE.ARM64),
        lief.MachO.parse(get_sample("MachO/IOKit")).take(lief.MachO.Header.CPU_TYPE.ARM),
    ])

    assert fat is not None
    assert len(fat) == 2

    fat = lief.MachO.FatBinary.create([
        lief.MachO.parse(get_sample("MachO/variants_alt.dylib")).take(lief.MachO.Header.CPU_TYPE.ARM64),
        lief.MachO.parse(get_sample("MachO/variants_alt.dylib")).take(lief.MachO.Header.CPU_TYPE.ARM64),
    ])
    assert fat is None
