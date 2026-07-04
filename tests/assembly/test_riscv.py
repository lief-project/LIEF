import lief
import pytest
from utils import parse_elf

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)


def test_riscv64():
    elf = parse_elf("ELF/i872_risv.elf")
    instructions = list(elf.disassemble(0x80000000))
    assert len(instructions) == 12504

    assert instructions[8] is not None
    assert instructions[8].address == 0x80000020
    assert instructions[8].to_string() == "0x80000020: li a7, -0x1"
    assert instructions[8].mnemonic == "c.li"
    assert isinstance(instructions[8], lief.assembly.riscv.Instruction)
    assert instructions[8].opcode == lief.assembly.riscv.OPCODE.C_LI

    assert instructions[14] is not None
    assert instructions[14].address == 0x80000034
    assert instructions[14].to_string() == "0x80000034: amoadd.w a6, a7, (a6)"
    assert instructions[14].mnemonic == "amoadd.w"
    assert isinstance(instructions[14], lief.assembly.riscv.Instruction)
    assert instructions[14].opcode == lief.assembly.riscv.OPCODE.AMOADD_W


def test_riscv32():
    elf = parse_elf("ELF/elf_reader.riscv32.elf")
    start = 0x0001E810
    end = 0x0001E830
    instructions = list(elf.disassemble(0x0001E810, end - start))
    assert len(instructions) == 8
    assert instructions[0] is not None
    assert instructions[0].to_string() == "0x01e810: auipc t3, 0x43e"
    assert instructions[3] is not None
    assert instructions[3].to_string() == "0x01e81c: nop"
    assert instructions[6] is not None
    assert instructions[6].to_string() == "0x01e828: jalr t1, t3"
    assert isinstance(instructions[6], lief.assembly.riscv.Instruction)
    assert instructions[6].opcode == lief.assembly.riscv.OPCODE.JALR

    instructions = list(elf.disassemble(0x0006BE40, 0x30))

    assert len(instructions) == 18
    assert instructions[0] is not None
    assert instructions[0].to_string() == "0x06be40: addi sp, sp, -0x10"
    assert instructions[1] is not None
    assert instructions[1].to_string() == "0x06be42: sw s0, 0x8(sp)"
    assert instructions[2] is not None
    assert instructions[2].to_string() == "0x06be44: sw s1, 0x4(sp)"


def test_riscv_operands():
    # RV32: integer/register/memory operands
    elf = parse_elf("ELF/elf_reader.riscv32.elf")
    instructions = list(elf.disassemble(0x0006BE40, 0x30))

    # addi sp, sp, -0x10  ->  Register(sp), Register(sp), Immediate(-16)
    inst_0 = instructions[0]
    assert isinstance(inst_0, lief.assembly.riscv.Instruction)
    operands = list(inst_0.operands)
    assert len(operands) == 3
    assert isinstance(operands[0], lief.assembly.riscv.operands.Register)
    assert operands[0].value == lief.assembly.riscv.REG.X2
    assert isinstance(operands[1], lief.assembly.riscv.operands.Register)
    assert operands[1].value == lief.assembly.riscv.REG.X2
    assert isinstance(operands[2], lief.assembly.riscv.operands.Immediate)
    assert operands[2].value == -0x10

    # sw s0, 0x8(sp)  ->  Register(s0), Memory(base=sp, displacement=8)
    inst_1 = instructions[1]
    assert isinstance(inst_1, lief.assembly.riscv.Instruction)
    operands = list(inst_1.operands)
    assert len(operands) == 2
    assert isinstance(operands[0], lief.assembly.riscv.operands.Register)
    assert operands[0].value == lief.assembly.riscv.REG.X8
    assert isinstance(operands[1], lief.assembly.riscv.operands.Memory)
    assert operands[1].base == lief.assembly.riscv.REG.X2
    assert operands[1].displacement == 8

    # sw s1, 0x4(sp)  ->  Register(s1), Memory(base=sp, displacement=4)
    inst_2 = instructions[2]
    assert isinstance(inst_2, lief.assembly.riscv.Instruction)
    operands = list(inst_2.operands)
    assert isinstance(operands[1], lief.assembly.riscv.operands.Memory)
    assert operands[1].base == lief.assembly.riscv.REG.X2
    assert operands[1].displacement == 4


def test_riscv_sysreg_operand():
    # A CSR access exposes a Register operand whose value is a SYSREG (CSR)
    # rather than a regular REG.
    elf = parse_elf("ELF/i872_risv.elf")
    instructions = list(elf.disassemble(0x8000011C))

    inst_0 = instructions[0]
    assert isinstance(inst_0, lief.assembly.riscv.Instruction)
    operands = list(inst_0.operands)
    sysregs = [
        op.value
        for op in operands
        if isinstance(op, lief.assembly.riscv.operands.Register)
        and isinstance(op.value, lief.assembly.riscv.SYSREG)
    ]
    assert lief.assembly.riscv.SYSREG.mtvec in sysregs
