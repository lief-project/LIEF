import lief
from utils import get_sample, is_64bits_platform

def test_loongarch():
    elf = lief.ELF.parse(get_sample('ELF/art_reader.loongarch'))

    assert elf.header.machine_type == lief.ELF.ARCH.LOONGARCH

    relocation = elf.relocations[0]
    assert relocation.size == 26
    assert relocation.type == int(lief.ELF.Relocation.TYPE.LARCH_B26)
