import lief

from utils import get_sample

def test_mipsel():
    elf = lief.ELF.parse(get_sample("ELF/libdep_mipsel.so"))
    assert elf.header.flags_list == [
        lief.ELF.PROCESSOR_FLAGS.MIPS_NOREORDER, lief.ELF.PROCESSOR_FLAGS.MIPS_PIC,
        lief.ELF.PROCESSOR_FLAGS.MIPS_CPIC, lief.ELF.PROCESSOR_FLAGS.MIPS_ABI_O32,
        lief.ELF.PROCESSOR_FLAGS.MIPS_ARCH_32R2
    ]

    assert elf.get_section(".MIPS.abiflags").type == lief.ELF.Section.TYPE.MIPS_ABIFLAGS
    assert elf.get_section(".reginfo").type == lief.ELF.Section.TYPE.MIPS_REGINFO

    assert elf.segments[1].type == lief.ELF.Segment.TYPE.MIPS_REGINFO

    assert elf.get(lief.ELF.DynamicEntry.TAG.MIPS_RLD_VERSION).value == 1
    assert elf.get(lief.ELF.DynamicEntry.TAG.MIPS_FLAGS).value == 2
    assert elf.get(lief.ELF.DynamicEntry.TAG.MIPS_BASE_ADDRESS).value == 0
    assert elf.get(lief.ELF.DynamicEntry.TAG.MIPS_LOCAL_GOTNO).value == 9
    assert elf.get(lief.ELF.DynamicEntry.TAG.MIPS_SYMTABNO).value == 21
    assert elf.get(lief.ELF.DynamicEntry.TAG.MIPS_UNREFEXTNO).value == 35
    assert elf.get(lief.ELF.DynamicEntry.TAG.MIPS_GOTSYM).value == 3

    if lief.__extended__:
        inst = list(elf.disassemble("onload"))
        assert len(inst) == 191
        assert inst[0].to_string() == "0x000fa4: lui $gp, 2"
        assert inst[190].to_string() == "0x00129c: nop"
