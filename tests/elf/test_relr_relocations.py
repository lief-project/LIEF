import lief
import ctypes
from utils import get_sample, glibc_version
from pathlib import Path


def test_relr_relocations(tmp_path: Path):
    elf = lief.ELF.parse(get_sample('ELF/libm-ubuntu24.so'))

    relr_reloc = [r for r in elf.relocations if r.encoding == lief.ELF.Relocation.ENCODING.RELR]
    assert len(relr_reloc) == 3

    assert relr_reloc[0].address == 0xe9c48
    assert relr_reloc[0].type == lief.ELF.Relocation.TYPE.X86_64_RELATIVE

    assert relr_reloc[1].address == 0xe9c50
    assert relr_reloc[1].type == lief.ELF.Relocation.TYPE.X86_64_RELATIVE

    assert relr_reloc[2].address == 0xea000
    assert relr_reloc[2].type == lief.ELF.Relocation.TYPE.X86_64_RELATIVE

    out = tmp_path / "libm.so.6"

    builder = lief.ELF.Builder(elf)
    builder.config.force_relocate = True
    builder.build()
    builder.write(out.as_posix())

    new = lief.ELF.parse(out.as_posix())

    new_relr_reloc = [r for r in new.relocations if r.encoding == lief.ELF.Relocation.ENCODING.RELR]
    assert len(new_relr_reloc) == 3

    assert new_relr_reloc[0].address == 0x1000 + 0xe9c48
    assert new_relr_reloc[1].address == 0x1000 + 0xe9c50
    assert new_relr_reloc[2].address == 0x1000 + 0xea000

    if (2, 38) <= glibc_version():
        print("Trying to load libm.so")
        out.chmod(0o755)
        lib = ctypes.cdll.LoadLibrary(out.as_posix())
        assert lib.cos is not None

