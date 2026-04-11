import os
import pathlib
import stat
import subprocess
from pathlib import Path
from subprocess import Popen

import lief
import pytest
from utils import glibc_version, is_linux, parse_elf

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
    lief.logging.warn(f"glibc version is too old: {version}")


def normalize(instr: str) -> str:
    instr = instr.replace("\n", "").replace(" ", "").strip()
    return instr


def build_run_check(obj: pathlib.Path, new_object: pathlib.Path):
    out_bin = new_object.parent / f"{new_object.name}.bin"
    lief.logging.info(f"Executable: {out_bin}")
    CXX = os.getenv("CXX", "g++")

    extra_flags = []
    if ".nopie." in obj.name:
        extra_flags.append("-no-pie")
    cmd = (
        [CXX, new_object.as_posix(), "-o", out_bin.as_posix()]
        + extra_flags
        + ["-lpthread"]
    )
    with Popen(
        cmd, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    ) as proc:
        assert proc.stdout is not None
        stdout = proc.stdout.read()

        out_bin.chmod(out_bin.stat().st_mode | stat.S_IEXEC)
        with Popen(
            out_bin.as_posix(),
            universal_newlines=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        ) as proc:
            assert proc.stdout is not None
            stdout = proc.stdout.read()
            assert normalize(OUTPUT) == normalize(stdout)


@pytest.mark.skipif(
    not is_linux() or glibc_too_old, reason="not linux or glibc too old"
)
@pytest.mark.slow
def test_force_relocate(tmp_path: Path):
    BINS = SAMPLE_DIR / "ELF" / "batch-x86-64"
    tmp = pathlib.Path(tmp_path)
    for file in BINS.rglob("*.o"):
        lief.logging.info(f"Dealing with {file}")
        if not file.exists():
            lief.logging.warn(f"{file} does not exist. Skipping ...")
            continue
        elf_parsed = lief.ELF.parse(file)
        assert elf_parsed is not None
        elf: lief.ELF.Binary = elf_parsed

        config = lief.ELF.Builder.config_t()
        config.force_relocate = True

        out_path = tmp / Path(file.name).name

        lief.logging.info(f"File written in {out_path}")
        elf.write(out_path, config)
        build_run_check(file, out_path)


@pytest.mark.skipif(
    not is_linux() or glibc_too_old, reason="not linux or glibc too old"
)
def test_object_files_section(tmp_path: Path):
    BINS = SAMPLE_DIR / "ELF" / "batch-x86-64"
    tmp = pathlib.Path(tmp_path)
    for file in BINS.rglob("*.o"):
        lief.logging.info(f"Dealing with {file}")
        if not file.exists():
            lief.logging.warn(f"{file} does not exist. Skipping ...")
            continue
        elf_parsed = lief.ELF.parse(file)
        assert elf_parsed is not None
        elf: lief.ELF.Binary = elf_parsed

        symtab = elf.get_section(".symtab")
        assert symtab is not None
        symtab.name = ".foooooootab"

        out_path = tmp / file.name

        lief.logging.info(f"File written in {out_path}")
        elf.write(out_path)
        build_run_check(file, out_path)


@pytest.mark.skipif(
    not is_linux() or glibc_too_old, reason="not linux or glibc too old"
)
def test_object_files_symbols(tmp_path: Path):
    BINS = SAMPLE_DIR / "ELF" / "batch-x86-64"
    tmp = pathlib.Path(tmp_path)
    for file in BINS.rglob("*.o"):
        lief.logging.info(f"Dealing with {file}")
        if not file.exists():
            lief.logging.warn(f"{file} does not exist. Skipping ...")
            continue
        elf_parsed = lief.ELF.parse(file)
        assert elf_parsed is not None
        elf: lief.ELF.Binary = elf_parsed

        sym = lief.ELF.Symbol()
        sym.name = "LIEF_CUSTOM_SYMBOL"
        sym.type = lief.ELF.Symbol.TYPE.NOTYPE
        sym.visibility = lief.ELF.Symbol.VISIBILITY.DEFAULT
        sym.binding = (
            lief.ELF.Symbol.BINDING.GLOBAL
        )  # TODO(romain): it fails if the symbol is "local"
        # cf. binutils-2.35.1/bfd/elflink.c:4602
        sym.value = 0xDEADC0DE
        elf.add_symtab_symbol(sym)

        # Modify an existing one
        file_sym = elf.get_symtab_symbol("test.cpp")
        assert file_sym is not None
        file_sym.name = "/tmp/foobar.cpp"

        out_path = tmp / file.name

        lief.logging.info(f"File written in {out_path}")
        elf.write(out_path)
        build_run_check(file, out_path)


@pytest.mark.skipif(
    not is_linux() or glibc_too_old, reason="not linux or glibc too old"
)
def test_relocations(tmp_path: Path):
    BINS = SAMPLE_DIR / "ELF" / "batch-x86-64"
    tmp = pathlib.Path(tmp_path)
    for file in BINS.rglob("*.o"):
        lief.logging.info(f"Dealing with {file}")
        if not file.exists():
            lief.logging.warn(f"{file} does not exist. Skipping ...")
            continue
        elf_parsed = lief.ELF.parse(file)
        assert elf_parsed is not None
        elf: lief.ELF.Binary = elf_parsed

        # Add a relocation that do "nothing"
        rel = lief.ELF.Relocation(lief.ELF.ARCH.X86_64)
        rel.addend = 123
        rel.address = 0x123
        rel.type = lief.ELF.Relocation.TYPE.X86_64_NONE
        rel.purpose = lief.ELF.Relocation.PURPOSE.OBJECT
        text_section = elf.get_section(".text")
        assert text_section is not None
        elf.add_object_relocation(rel, text_section)

        out_path = tmp / file.name

        lief.logging.info(f"File written in {out_path}")
        elf.write(out_path)
        build_run_check(file, out_path)


def test_relocation_resolve():
    elf = parse_elf("ELF/issue_975_aarch64.o")
    assert elf.relocations[0].resolve() == 0xFFFFFFE4
