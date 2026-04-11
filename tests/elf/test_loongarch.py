import lief
from utils import parse_elf


def test_loongarch():
    elf = parse_elf("ELF/art_reader.loongarch")

    assert elf.header.machine_type == lief.ELF.ARCH.LOONGARCH

    relocation = elf.relocations[0]
    assert relocation.size == 26
    assert relocation.type == lief.ELF.Relocation.TYPE.LARCH_B26
