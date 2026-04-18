import os
import stat
import subprocess
from pathlib import Path
from subprocess import Popen

import lief
import pytest
from utils import glibc_version, is_linux, lief_samples_dir, parse_elf

BATCH_DIR = lief_samples_dir() / "ELF/batch-x86-64"

_OUTPUT = """
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


def _normalize(instr: str) -> str:
    instr = instr.replace("\n", "").replace(" ", "").strip()
    return instr


def build_run_check(obj: Path, new_object: Path):
    if not is_linux() or glibc_version() < (2, 32):
        return
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
            assert _normalize(_OUTPUT) == _normalize(stdout)


@pytest.mark.slow
def test_force_relocate(tmp_path: Path):
    for file in BATCH_DIR.rglob("*.o"):
        lief.logging.info(f"Dealing with {file}")
        elf = parse_elf(file)

        config = lief.ELF.Builder.config_t()
        config.force_relocate = True

        out_path = tmp_path / file.name

        lief.logging.info(f"File written in {out_path}")
        elf.write(out_path, config)
        build_run_check(file, out_path)


def test_object_files_section(tmp_path: Path):
    for file in BATCH_DIR.rglob("*.o"):
        lief.logging.info(f"Dealing with {file}")
        elf = parse_elf(file)

        symtab = elf.get_section(".symtab")
        assert symtab is not None
        symtab.name = ".foooooootab"

        out_path = tmp_path / file.name

        lief.logging.info(f"File written in {out_path}")
        elf.write(out_path)
        build_run_check(file, out_path)


def test_object_files_symbols(tmp_path: Path):
    for file in BATCH_DIR.rglob("*.o"):
        lief.logging.info(f"Dealing with {file}")
        elf = parse_elf(file)

        sym = lief.ELF.Symbol()
        sym.name = "LIEF_CUSTOM_SYMBOL"
        sym.type = lief.ELF.Symbol.TYPE.NOTYPE
        sym.visibility = lief.ELF.Symbol.VISIBILITY.DEFAULT

        # TODO(romain): it fails if the symbol is "local"
        # cf. binutils-2.35.1/bfd/elflink.c:4602
        sym.binding = lief.ELF.Symbol.BINDING.GLOBAL

        sym.value = 0xDEADC0DE
        elf.add_symtab_symbol(sym)

        # Modify an existing one
        file_sym = elf.get_symtab_symbol("test.cpp")
        assert file_sym is not None
        file_sym.name = "/tmp/foobar.cpp"

        out_path = tmp_path / file.name

        lief.logging.info(f"File written in {out_path}")
        elf.write(out_path)
        build_run_check(file, out_path)


def test_relocations(tmp_path: Path):
    for file in BATCH_DIR.rglob("*.o"):
        lief.logging.info(f"Dealing with {file}")
        elf = parse_elf(file)

        # Add a relocation that do "nothing"
        rel = lief.ELF.Relocation(lief.ELF.ARCH.X86_64)
        rel.addend = 123
        rel.address = 0x123
        rel.type = lief.ELF.Relocation.TYPE.X86_64_NONE
        rel.purpose = lief.ELF.Relocation.PURPOSE.OBJECT
        text_section = elf.get_section(".text")
        assert text_section is not None
        elf.add_object_relocation(rel, text_section)

        out_path = tmp_path / file.name

        lief.logging.info(f"File written in {out_path}")
        elf.write(out_path)
        build_run_check(file, out_path)


def test_relocation_resolve():
    elf = parse_elf("ELF/issue_975_aarch64.o")
    assert elf.relocations[0].resolve() == 0xFFFFFFE4
