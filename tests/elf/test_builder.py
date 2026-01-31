#!/usr/bin/env python
import lief
import math
import os
import pathlib
import stat
import subprocess
import sys
import pytest
import shutil
from pathlib import Path
from textwrap import dedent

from subprocess import Popen
from utils import (
    is_linux, glibc_version, get_sample,
    has_private_samples, is_server_ci, ci_runner_arch, is_windows,
    is_x86_64, is_github_ci
)

# pyright: reportOptionalMemberAccess=false

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

def test_issue_1121(tmp_path: Path):
    elf = lief.ELF.parse(get_sample("ELF/issue_1121.elf"))
    elf.get_symbol("main").name = "main_test"

    out = tmp_path / "main_test.new"
    elf.write(out.as_posix())

    new = lief.ELF.parse(out)
    assert new.has_symbol("main_test")


@pytest.mark.skipif(not has_private_samples(), reason="needs private samples")
def test_smart_insert_1(tmp_path: Path):
    """
    The purpose of this test is to make sure that when we have a binary with debug
    info (or not) and we insert a new section/segment, the section is inserted
    prior the debug info so that stripping the binary works
    """
    if is_server_ci() and not ci_runner_arch().startswith("linux/"):
        pytest.skip("skipping: needs linux runner")
    input_path = Path(get_sample("private/ELF/libclang-cpp.so.20.1"))
    elf = lief.ELF.parse(input_path)

    section = lief.ELF.Section(".lief_test")
    section.content = list(b"This is a test")
    elf.add(section)

    output = tmp_path / input_path.name
    elf.write(output.as_posix())

    new_elf = lief.ELF.parse(output)

    sec = new_elf.get_section(".lief_test")
    assert new_elf.get_section_idx(sec) == 27

    if is_linux():
        llvm_strip = shutil.which("llvm-strip")
        if llvm_strip is None:
            pytest.skip("skipping: missing 'llvm-strip'")
        print(f"Using llvm-strip: {llvm_strip}")
        popen_args = {
            "universal_newlines": True,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT,
        }

        args = [
            llvm_strip,
            output.as_posix()
        ]
        with Popen(args, **popen_args) as proc: # type: ignore[call-overload]
            stdout, _ = proc.communicate(timeout=10)
            print("stdout:", stdout)
            assert proc.returncode == 0
            assert len(stdout) == 0

        elf_strip = lief.ELF.parse(output)
        lief_test_section: lief.ELF.Section = elf_strip.get_section(".lief_test")
        assert lief_test_section is not None
        print(bytes(lief_test_section.content))
        assert bytes(lief_test_section.content) == b'This is a test\x00\x00'

@pytest.mark.skipif(not has_private_samples(), reason="needs private samples")
def test_smart_insert_2(tmp_path: Path):
    input_path = Path(get_sample("private/ELF/libhwui.so"))
    elf = lief.ELF.parse(input_path)

    section = lief.ELF.Section(".lief_section_to_strip")
    section.content = list(b"The content of this section needs to be removed")
    elf.add(section, loaded=False)

    output = tmp_path / input_path.name
    elf.write(output.as_posix())

    new_elf = lief.ELF.parse(output)

    sec = new_elf.get_section(".lief_section_to_strip")
    assert new_elf.get_section_idx(sec) == 25

    if is_linux():
        llvm_strip = shutil.which("llvm-strip")
        if llvm_strip is None:
            pytest.skip("skipping: missing 'llvm-strip'")

        print(f"Using llvm-strip: {llvm_strip}")
        popen_args = {
            "universal_newlines": True,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT,
        }

        args = [
            llvm_strip,
            output.as_posix()
        ]

        with Popen(args, **popen_args) as proc: # type: ignore[call-overload]
            stdout, _ = proc.communicate(timeout=10)
            print("stdout:", stdout)
            assert proc.returncode == 0
            assert len(stdout) == 0

        elf_strip = lief.ELF.parse(output)
        lief_test_section: lief.ELF.Section = elf_strip.get_section(".lief_section_to_strip")
        assert lief_test_section is None

def test_issue_1175_missing_segment(tmp_path: Path):
    elf = lief.ELF.parse(get_sample("ELF/issue_1175.elf"))
    for i in range(2):
        section = lief.ELF.Section(f".lief.dummy.{i + 1}")
        section.content = list(b"Hello World")
        elf.add(section)

    output = tmp_path / "issue_1175.elf"
    elf.write(output.as_posix())

    new = lief.ELF.parse(output)
    assert new.get(lief.ELF.Segment.TYPE.RISCV_ATTRIBUTES) is not None
    stacksize_content = lief.dump(new.get_section(".stack_sizes").content)
    #print("\n" + stacksize_content)
    assert stacksize_content == dedent("""\
    +---------------------------------------------------------------------+
    | 9c 00 02 00 10 9c 01 02 00 10 14 02 02 00 00 6e  | ...............n |
    | 02 02 00 00 70 02 02 00 00 72 02 02 00 00 74 02  | ....p....r....t. |
    | 02 00 00 80 02 02 00 00                          | ........         |
    +---------------------------------------------------------------------+""")

def test_ld_relocations(tmp_path: Path):
    elf = lief.ELF.parse(get_sample("ELF/ld-linux-x32.so.2"))
    elf.relocate_phdr_table()

    config = lief.ELF.Builder.config_t()
    config.force_relocate = True
    output = tmp_path / "ld.so"
    elf.write(output.as_posix(), config)
    output.chmod(0o755)

    new = lief.ELF.parse(output)
    assert new.header.program_header_offset == 52

    if is_linux() and is_x86_64() and not is_github_ci():
        with Popen([output.as_posix(), "--version"], universal_newlines=True,
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
            stdout = proc.stdout.read()
            proc.poll()
            assert "version 2.41" in stdout


def test_s390x(tmp_path: Path):
    elf = lief.ELF.parse(get_sample("ELF/s390x-linux-gnu-libc.so"))

    r = elf.get_relocation("_dl_exception_create")
    assert r.address == 0x1c5008
    assert int.from_bytes(elf.get_content_from_virtual_address(r.address, 8), byteorder='big') == 0x2b07e

    output = tmp_path / "s390x-linux-gnu-libc.so"

    elf.relocate_phdr_table()

    config = lief.ELF.Builder.config_t()
    config.force_relocate = True

    elf.write(output.as_posix(), config)
    new = lief.ELF.parse(output)

    if is_github_ci() and is_windows():
        pytest.skip("Not supported")
        return

    r = new.get_relocation("_dl_exception_create")
    assert r.address == 0x1c6008
    assert int.from_bytes(elf.get_content_from_virtual_address(r.address, 8), byteorder='big') == 0x2c07e

    assert new.dynamic_entries[18].flags == [lief.ELF.DynamicEntryFlags.FLAG.STATIC_TLS]

def test_patchelf(tmp_path: Path):
    elf = lief.ELF.parse(get_sample("ELF/lief-patchelf"))
    elf.relocate_phdr_table()

    config = lief.ELF.Builder.config_t()
    config.force_relocate = True
    config.skip_dynamic = True

    output = tmp_path / "lief-patchelf"

    elf.write(output.as_posix(), config)

    output.chmod(0o755)

    if is_linux() and is_x86_64():
        with Popen([output.as_posix(), "--version"], universal_newlines=True,
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
            stdout = proc.stdout.read()
            proc.poll()
            assert "0.17.0.0" in stdout

def test_remove_segment(tmp_path: Path):
    elf = lief.ELF.parse(get_sample("ELF/lief-patchelf"))

    elf.remove(lief.ELF.Segment.TYPE.GNU_RELRO)
    elf.remove(lief.ELF.Segment.TYPE.GNU_STACK)
    elf.remove(lief.ELF.Segment.TYPE.NOTE)
    elf.remove(lief.ELF.Segment.TYPE.GNU_EH_FRAME)

    output = tmp_path / "lief-patchelf"

    elf.write(output.as_posix())

    new = lief.ELF.parse(output)

    assert new.get(lief.ELF.Segment.TYPE.GNU_EH_FRAME) is None

    if is_linux() and is_x86_64():
        output.chmod(0o755)
        with Popen([output.as_posix(), "--version"], universal_newlines=True,
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
            stdout = proc.stdout.read()
            proc.poll()
            assert "0.17.0.0" in stdout

def test_issue_1251():
    elf = lief.ELF.parse(get_sample("ELF/libmmkv.so"))
    assert elf.relocate_phdr_table() == 64
