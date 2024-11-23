import lief
import pytest
from utils import get_sample

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

def test_riscv64():
    elf = lief.ELF.parse(get_sample("ELF/i872_risv.elf"))
    instructions = list(elf.disassemble(0x80000000))
    assert len(instructions) == 12504

    assert instructions[8].address == 0x80000020
    assert instructions[8].to_string() == "0x80000020: li a7, -1"
    assert instructions[8].mnemonic == "c.li"
    assert isinstance(instructions[8], lief.assembly.riscv.Instruction)
    assert instructions[8].opcode == lief.assembly.riscv.OPCODE.C_LI

    assert instructions[14].address == 0x80000034
    assert instructions[14].to_string() == "0x80000034: amoadd.w a6, a7, (a6)"
    assert instructions[14].mnemonic == "amoadd.w"
    assert isinstance(instructions[14], lief.assembly.riscv.Instruction)
    assert instructions[14].opcode == lief.assembly.riscv.OPCODE.AMOADD_W

def test_riscv32():
    elf = lief.ELF.parse(get_sample("ELF/elf_reader.riscv32.elf"))
    start = 0x0001e810
    end = 0x0001e830
    instructions = list(elf.disassemble(0x0001e810, end - start))
    assert len(instructions) == 8
    assert instructions[0].to_string() == "0x01e810: auipc t3, 1086"
    assert instructions[3].to_string() == "0x01e81c: nop"
    assert instructions[6].to_string() == "0x01e828: jalr t1, t3"
    assert isinstance(instructions[6], lief.assembly.riscv.Instruction)
    assert instructions[6].opcode == lief.assembly.riscv.OPCODE.JALR

    instructions = list(elf.disassemble(0x0006be40, 0x30))

    assert len(instructions) == 18
    assert instructions[0].to_string() == "0x06be40: addi sp, sp, -16"
    assert instructions[1].to_string() == "0x06be42: sw s0, 8(sp)"
    assert instructions[2].to_string() == "0x06be44: sw s1, 4(sp)"
