#!/usr/bin/env python
import lief
import os
import pathlib
import stat
import subprocess
import sys
import pytest
from pathlib import Path

from subprocess import Popen
from utils import is_linux, glibc_version

SAMPLE_DIR = Path(os.getenv("LIEF_SAMPLES_DIR", ""))

OUTPUT = """
In ctor
In ctor2
sum: 3
In dtor2
In dtor
LOOKUP_RO[0]: 0
LOOKUP_RO[1]: 11111111
LOOKUP_RW[0]: 0
LOOKUP_RW[1]: 11111111
"""


version = glibc_version()
glibc_too_old = False

if version < (2, 32):
    glibc_too_old = True
    print(f"glibc version is too old: {version}")

def normalize(instr: str) -> str:
    instr = instr.replace("\n", "").replace(" ", "").strip()
    return instr

def build_run_check(obj: pathlib.Path, new_object: pathlib.Path):
    out_bin = new_object.parent / f"{new_object.name}.bin"
    print(f"Executable: {out_bin}")
    CXX = os.getenv("CXX", "g++")

    extra_flags = []
    if ".nopie." in obj.name:
        extra_flags.append("-no-pie")
    cmd = [CXX, new_object.as_posix(), "-o", out_bin.as_posix()] + extra_flags + ["-lpthread"]
    with Popen(cmd, universal_newlines=True,
               stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:

        stdout = proc.stdout.read()

        out_bin.chmod(out_bin.stat().st_mode | stat.S_IEXEC)
        with Popen(out_bin.as_posix(), universal_newlines=True,
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
            stdout = proc.stdout.read()
            assert normalize(OUTPUT) == normalize(stdout)

@pytest.mark.skipif(not is_linux() or glibc_too_old, reason="not linux or glibc too old")
def test_force_relocate(tmp_path):
    BINS = SAMPLE_DIR / "ELF" / "batch-x86-64"
    tmp = pathlib.Path(tmp_path)
    for file in BINS.rglob("*.o"):
        print(f"Dealing with {file}")
        if not file.exists():
            print(f"{file} does not exist. Skipping ...", file=sys.stderr)
            continue
        elf: lief.ELF.Binary = lief.ELF.parse(file.as_posix())

        builder = lief.ELF.Builder(elf)
        builder.config.force_relocate = True
        builder.build()

        out_path = tmp / Path(file.name).name

        print(f"File written in {out_path}")
        builder.write(out_path.as_posix())
        build_run_check(file, out_path)


@pytest.mark.skipif(not is_linux() or glibc_too_old, reason="not linux or glibc too old")
def test_object_files_section(tmp_path):
    BINS = SAMPLE_DIR / "ELF" / "batch-x86-64"
    tmp = pathlib.Path(tmp_path)
    for file in BINS.rglob("*.o"):
        print(f"Dealing with {file}")
        if not file.exists():
            print(f"{file} does not exist. Skipping ...", file=sys.stderr)
            continue
        elf: lief.ELF.Binary = lief.ELF.parse(file.as_posix())

        elf.get_section(".symtab").name = ".foooooootab"

        builder = lief.ELF.Builder(elf)
        builder.build()

        out_path = tmp / file.name

        print(f"File written in {out_path}")
        builder.write(out_path.as_posix())
        build_run_check(file, out_path)

@pytest.mark.skipif(not is_linux() or glibc_too_old, reason="not linux or glibc too old")
def test_object_files_symbols(tmp_path):
    BINS = SAMPLE_DIR / "ELF" / "batch-x86-64"
    tmp = pathlib.Path(tmp_path)
    for file in BINS.rglob("*.o"):
        print(f"Dealing with {file}")
        if not file.exists():
            print(f"{file} does not exist. Skipping ...", file=sys.stderr)
            continue
        elf: lief.ELF.Binary = lief.ELF.parse(file.as_posix())

        sym = lief.ELF.Symbol()
        sym.name       = "LIEF_CUSTOM_SYMBOL"
        sym.type       = lief.ELF.Symbol.TYPE.NOTYPE
        sym.visibility = lief.ELF.Symbol.VISIBILITY.DEFAULT
        sym.binding    = lief.ELF.Symbol.BINDING.GLOBAL # TODO(romain): it fails if the symbol is "local"
                                                         # cf. binutils-2.35.1/bfd/elflink.c:4602
        sym.value = 0xdeadc0de
        elf.add_symtab_symbol(sym)

        # Modify an existing one
        file_sym = elf.get_symtab_symbol("test.cpp")
        file_sym.name = "/tmp/foobar.cpp"

        builder = lief.ELF.Builder(elf)
        builder.build()

        out_path = tmp / file.name

        print(f"File written in {out_path}")
        builder.write(out_path.as_posix())
        build_run_check(file, out_path)


@pytest.mark.skipif(not is_linux() or glibc_too_old, reason="not linux or glibc too old")
def test_relocations(tmp_path):
    BINS = SAMPLE_DIR / "ELF" / "batch-x86-64"
    tmp = pathlib.Path(tmp_path)
    for file in BINS.rglob("*.o"):
        print(f"Dealing with {file}")
        if not file.exists():
            print(f"{file} does not exist. Skipping ...", file=sys.stderr)
            continue
        elf: lief.ELF.Binary = lief.ELF.parse(file.as_posix())

        # Add a relocation that do "nothing"
        rel = lief.ELF.Relocation(lief.ELF.ARCH.X86_64)
        rel.addend  = 123
        rel.address = 0x123
        rel.type    = lief.ELF.Relocation.TYPE.X86_64_NONE
        rel.purpose = lief.ELF.Relocation.PURPOSE.OBJECT
        elf.add_object_relocation(rel, elf.get_section(".text"))

        builder = lief.ELF.Builder(elf)
        builder.build()

        out_path = tmp / file.name

        print(f"File written in {out_path}")
        builder.write(out_path.as_posix())
        build_run_check(file, out_path)
