import pathlib
import stat
import subprocess
from pathlib import Path
from random import shuffle

import lief
from utils import is_linux, parse_elf


def test_frame(tmp_path: Path):
    elf = parse_elf("ELF/mbedtls_selftest.elf64")

    assert len(elf.dynamic_entries) == 26

    for section in elf.sections:
        if section.virtual_address == 0:
            continue

        section.as_frame()
        section.type = lief.ELF.Section.TYPE.ARM_EXIDX
        section.virtual_address = 0xDEADC0DE
        section.offset = 0xDEADC0DE
        section.size = 0xDEADC0DE
        name: list[str] = list(section.name)  # type: ignore
        shuffle(name)
        section.name = "".join(name)

    elf.add_library(elf.libraries[0])  # type: ignore

    out = pathlib.Path(tmp_path) / "mbedtls_selftest.elf64"
    elf.write(out)

    new = lief.ELF.parse(out)
    assert new is not None

    out.chmod(out.stat().st_mode | stat.S_IEXEC)
    assert (
        len(new.dynamic_entries) == 27
    )  # Make sure our modifications has been committed

    if is_linux():
        assert isinstance(
            subprocess.run(out.as_posix(), check=True), subprocess.CompletedProcess
        )


def test_sectionless(tmp_path: Path):
    elf: lief.ELF.Binary = parse_elf("ELF/mbedtls_selftest.elf64")

    assert len(elf.dynamic_symbols) == 40

    header: lief.ELF.Header = elf.header

    header.numberof_sections = 0
    header.section_header_offset = 0

    out = pathlib.Path(tmp_path) / "mbedtls_selftest.sectionless"
    elf.write(out)

    sectionless = lief.ELF.parse(out)
    assert sectionless is not None
    out = pathlib.Path(tmp_path) / "mbedtls_selftest.sectionless.built"

    assert len(sectionless.dynamic_symbols) == 40

    sectionless.add_library(sectionless.libraries[0])  # type: ignore
    sectionless.write(out)

    out.chmod(out.stat().st_mode | stat.S_IEXEC)

    new = lief.ELF.parse(out)
    assert new is not None
    assert (
        len(new.dynamic_entries) == 27
    )  # Make sure our modifications has been committed

    if is_linux():
        assert isinstance(
            subprocess.run(out.as_posix(), check=True), subprocess.CompletedProcess
        )
