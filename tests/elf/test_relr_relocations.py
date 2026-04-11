import ctypes
from pathlib import Path

import lief
from utils import check_layout, glibc_version, parse_elf


def test_relr_relocations(tmp_path: Path):
    elf = parse_elf("ELF/libm-ubuntu24.so")

    relr_reloc = [
        r for r in elf.relocations if r.encoding == lief.ELF.Relocation.ENCODING.RELR
    ]
    assert len(relr_reloc) == 3

    assert relr_reloc[0].address == 0xE9C48
    assert relr_reloc[0].type == lief.ELF.Relocation.TYPE.X86_64_RELATIVE

    assert relr_reloc[1].address == 0xE9C50
    assert relr_reloc[1].type == lief.ELF.Relocation.TYPE.X86_64_RELATIVE

    assert relr_reloc[2].address == 0xEA000
    assert relr_reloc[2].type == lief.ELF.Relocation.TYPE.X86_64_RELATIVE

    out = tmp_path / "libm.so.6"

    config = lief.ELF.Builder.config_t()
    config.force_relocate = True
    elf.write(out, config)

    new = lief.ELF.parse(out)
    assert new is not None

    check_layout(new)
    new_relr_reloc = [
        r for r in new.relocations if r.encoding == lief.ELF.Relocation.ENCODING.RELR
    ]
    assert len(new_relr_reloc) == 3

    assert new_relr_reloc[0].address == 0x1000 + 0xE9C48
    assert new_relr_reloc[1].address == 0x1000 + 0xE9C50
    assert new_relr_reloc[2].address == 0x1000 + 0xEA000

    if (2, 38) <= glibc_version():
        lief.logging.info("Trying to load libm.so")
        out.chmod(0o755)
        lib = ctypes.cdll.LoadLibrary(out.as_posix())
        assert lib.cos is not None


def test_relr_addend(tmp_path: Path):
    elf = parse_elf("ELF/ls-glibc2.40-relr.elf")
    elf.relocate_phdr_table()
    out = tmp_path / "out.elf"
    elf.write(out)

    new_elf = lief.ELF.parse(out)
    assert new_elf is not None
    check_layout(new_elf)
    assert new_elf.get_int_from_virtual_address(0x21F40, 8) == 0xA680
