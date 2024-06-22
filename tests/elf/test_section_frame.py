import lief
import pathlib
import stat
import subprocess
from random import shuffle

from utils import get_sample, is_linux

lief.logging.set_level(lief.logging.LEVEL.DEBUG)

def test_frame(tmp_path):
    elf = lief.ELF.parse(get_sample("ELF/mbedtls_selftest.elf64"))

    assert len(elf.dynamic_entries) == 26

    for section in elf.sections:
        if section.virtual_address == 0:
            continue

        section.as_frame()
        section.type            = lief.ELF.Section.TYPE.ARM_EXIDX
        section.virtual_address = 0xdeadc0de
        section.offset          = 0xdeadc0de
        section.size            = 0xdeadc0de
        name: list[str] = list(section.name) # type: ignore
        shuffle(name)
        section.name = "".join(name)

    elf.add_library(elf.libraries[0]) # type: ignore

    out = pathlib.Path(tmp_path) / "mbedtls_selftest.elf64"
    elf.write(out.as_posix())

    new = lief.ELF.parse(out.as_posix())

    out.chmod(out.stat().st_mode | stat.S_IEXEC)
    assert len(new.dynamic_entries) == 27 # Make sure our modifications has been committed

    if is_linux():
        assert isinstance(subprocess.run(out.as_posix(), check=True), subprocess.CompletedProcess)

def test_sectionless(tmp_path):
    elf: lief.ELF.Binary = lief.ELF.parse(get_sample("ELF/mbedtls_selftest.elf64"))

    assert len(elf.dynamic_symbols) == 40

    header: lief.ELF.Header = elf.header

    header.numberof_sections     = 0
    header.section_header_offset = 0

    out = pathlib.Path(tmp_path) / "mbedtls_selftest.sectionless"
    elf.write(out.as_posix())

    sectionless = lief.ELF.parse(out.as_posix())
    out = pathlib.Path(tmp_path) / "mbedtls_selftest.sectionless.built"

    assert len(sectionless.dynamic_symbols) == 40

    sectionless.add_library(sectionless.libraries[0]) # type: ignore
    sectionless.write(out.as_posix())

    out.chmod(out.stat().st_mode | stat.S_IEXEC)

    new = lief.ELF.parse(out.as_posix())
    assert len(new.dynamic_entries) == 27 # Make sure our modifications has been committed

    if is_linux():
        assert isinstance(subprocess.run(out.as_posix(), check=True), subprocess.CompletedProcess)
