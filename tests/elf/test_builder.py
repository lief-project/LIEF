#!/usr/bin/env python
import lief
import math
import os
import pathlib
import stat
import subprocess
import sys
import pytest
from pathlib import Path

from subprocess import Popen
from utils import is_linux, glibc_version, get_sample

SAMPLE_DIR = pathlib.Path(os.getenv("LIEF_SAMPLES_DIR", ""))

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

def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return "%s %s" % (s, size_name[i])


@pytest.mark.skipif(not is_linux() or glibc_too_old, reason="not linux or glibc too old")
def test_force_relocate(tmp_path):
    SKIP_LIST = {
        "test.clang.gold.wronglinker.bin", "test.android.bin", "test.android.aarch64.bin",
        "test.rust.bin", "test.go.pie.bin", "test.clang.lld.nolinker.bin", "test.dart.bin",
        "test.clang.lld.tbss.tdata.nopie.bin", "test.go.static.bin"
    }
    BINS = SAMPLE_DIR / "ELF" / "batch-x86-64"
    tmp = pathlib.Path(tmp_path)
    for file in BINS.rglob("*.bin"):
        if file.name in SKIP_LIST:
            continue
        print(f"Dealing with {file}")
        if not file.exists():
            print(f"{file} does not exist. Skipping ...", file=sys.stderr)
            continue
        elf: lief.ELF.Binary = lief.ELF.parse(file.as_posix())
        fsize = file.stat().st_size

        builder = lief.ELF.Builder(elf)
        builder.config.force_relocate = True
        builder.build()

        out_path = tmp / file.name

        print(f"File written in {out_path}")
        builder.write(out_path.as_posix())

        out_path.chmod(out_path.stat().st_mode | stat.S_IEXEC)
        delta_size = out_path.stat().st_size - fsize
        print(f"delta size: {convert_size(delta_size)}")

        env = os.environ
        with Popen(out_path.as_posix(), universal_newlines=True, env=env,
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
            stdout = proc.stdout.read()
            proc.poll()
            assert normalize(OUTPUT) == normalize(stdout)


@pytest.mark.skipif(not is_linux() or glibc_too_old, reason="not linux or glibc too old")
def test_symtab(tmp_path):
    """
    Test that the ELF builder is able to manipulate the .symtab section
    """
    TARGETS = [
        SAMPLE_DIR / "ELF" / "batch-x86-64" / "test.clang.debug.bin",
        SAMPLE_DIR / "ELF" / "batch-x86-64" / "test.clang.stripped.bin",
        SAMPLE_DIR / "ELF" / "batch-x86-64" / "test.gcc.stripped.bin",
    ]
    NB_SYMBOLS = 30
    for TARGET in TARGETS:

        tmp = pathlib.Path(tmp_path)
        out_path = tmp / TARGET.name

        elf: lief.ELF.Binary = lief.ELF.parse(TARGET.as_posix())

        fsize = TARGET.stat().st_size
        for i in range(NB_SYMBOLS):
            sym = lief.ELF.Symbol()
            sym.name = "test_sym_{:03}".format(i)
            sym.value = 0x1000 + i
            sym.type = lief.ELF.Symbol.TYPE.FUNC
            sym.binding = lief.ELF.Symbol.BINDING.LOCAL
            sym.visibility = lief.ELF.Symbol.VISIBILITY.DEFAULT
            elf.add_symtab_symbol(sym)
        elf.write(out_path.as_posix())

        print(f"File written in {out_path}")
        out_path.chmod(out_path.stat().st_mode | stat.S_IEXEC)
        delta_size = out_path.stat().st_size - fsize
        print(f"delta size: {convert_size(delta_size)}")

        env = os.environ
        with Popen(out_path.as_posix(), universal_newlines=True, env=env,
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
            stdout = proc.stdout.read()
            proc.poll()
            assert normalize(OUTPUT) == normalize(stdout)


        out = lief.ELF.parse(out_path.as_posix())
        sym_names = [s.name for s in out.symtab_symbols]
        assert "test_sym_029" in sym_names

@pytest.mark.skipif(not is_linux() or glibc_too_old, reason="not linux or glibc too old")
def test_add_interpreter(tmp_path):
    TARGET = SAMPLE_DIR / "ELF" / "batch-x86-64" / "test.clang.lld.nolinker.bin"
    tmp = pathlib.Path(tmp_path)
    out_path = tmp / TARGET.name

    elf: lief.ELF.Binary = lief.ELF.parse(TARGET.as_posix())
    fsize = TARGET.stat().st_size

    elf.interpreter = "/lib64/ld-linux-x86-64.so.2"

    elf.write(out_path.as_posix())

    print(f"File written in {out_path}")
    out_path.chmod(out_path.stat().st_mode | stat.S_IEXEC)
    delta_size = out_path.stat().st_size - fsize
    print(f"delta size: {convert_size(delta_size)}")

    env = os.environ
    with Popen(out_path.as_posix(), universal_newlines=True, env=env,
               stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
        stdout = proc.stdout.read()
        proc.poll()
        assert normalize(OUTPUT) == normalize(stdout)

@pytest.mark.skipif(not is_linux() or glibc_too_old, reason="not linux or glibc too old")
def test_change_interpreter(tmp_path):
    TARGET = SAMPLE_DIR / "ELF" / "batch-x86-64" / "test.clang.gold.wronglinker.bin"
    tmp = pathlib.Path(tmp_path)
    out_path = tmp / TARGET.name

    elf: lief.ELF.Binary = lief.ELF.parse(TARGET.as_posix())
    fsize = TARGET.stat().st_size

    elf.interpreter = "/lib64/ld-linux-x86-64.so.2"

    elf.write(out_path.as_posix())

    print(f"File written in {out_path}")
    out_path.chmod(out_path.stat().st_mode | stat.S_IEXEC)
    delta_size = out_path.stat().st_size - fsize
    print(f"delta size: {convert_size(delta_size)}")

    env = os.environ
    with Popen(out_path.as_posix(), universal_newlines=True, env=env,
               stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
        stdout = proc.stdout.read()
        proc.poll()
        assert normalize(OUTPUT) == normalize(stdout)


@pytest.mark.skipif(not is_linux() or glibc_too_old, reason="not linux or glibc too old")
def test_rust_files(tmp_path):
    TARGET = SAMPLE_DIR / "ELF" / "batch-x86-64" / "test.rust.bin"
    tmp = pathlib.Path(tmp_path)
    out_path = tmp / TARGET.name

    elf: lief.ELF.Binary = lief.ELF.parse(TARGET.as_posix())
    fsize = TARGET.stat().st_size

    builder = lief.ELF.Builder(elf)
    builder.config.force_relocate = True
    builder.build()

    elf.write(out_path.as_posix())

    print(f"File written in {out_path}")
    out_path.chmod(out_path.stat().st_mode | stat.S_IEXEC)
    delta_size = out_path.stat().st_size - fsize
    print(f"delta size: {convert_size(delta_size)}")

    env = os.environ
    with Popen(out_path.as_posix(), universal_newlines=True, env=env,
               stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
        stdout = proc.stdout.read()
        proc.poll()
        assert "thisisthreadnumber9" in normalize(stdout)

@pytest.mark.skipif(not is_linux() or glibc_too_old, reason="not linux or glibc too old")
def test_go_files(tmp_path):
    TARGETS = [
        SAMPLE_DIR / "ELF" / "batch-x86-64" / "test.go.pie.bin",
        SAMPLE_DIR / "ELF" / "batch-x86-64" / "test.go.static.bin",
    ]
    for TARGET in TARGETS:
        tmp = pathlib.Path(tmp_path)
        out_path = tmp / TARGET.name

        elf: lief.ELF.Binary = lief.ELF.parse(TARGET.as_posix())
        fsize = TARGET.stat().st_size

        builder = lief.ELF.Builder(elf)
        builder.config.force_relocate = True
        builder.build()

        elf.write(out_path.as_posix())

        print(f"File written in {out_path}")
        out_path.chmod(out_path.stat().st_mode | stat.S_IEXEC)
        delta_size = out_path.stat().st_size - fsize
        print(f"delta size: {convert_size(delta_size)}")

        env = os.environ
        with Popen(out_path.as_posix(), universal_newlines=True, env=env,
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
            stdout = proc.stdout.read()
            proc.poll()
            assert "done" in normalize(stdout)

def test_issue_970(tmp_path: Path):
    lib = lief.ELF.parse(get_sample("ELF/libcudart.so.12"))
    out = tmp_path / "libcudart.so"

    lib.write(out.as_posix())
    new = lief.ELF.parse(out.as_posix())

    assert len(new.symbols_version_definition) == 2
    svd_0 = new.symbols_version_definition[0]
    svd_1 = new.symbols_version_definition[1]

    assert len(svd_0.auxiliary_symbols) == 1
    assert len(svd_1.auxiliary_symbols) == 1

    assert svd_0.auxiliary_symbols[0].name == "libcudart.so.12"
    assert svd_1.auxiliary_symbols[0].name == "libcudart.so.12"
