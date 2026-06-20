import lief
import pytest
from utils import parse_elf

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)


def test_mipsr3000():
    elf = parse_elf("ELF/echo.mips_r3000.bin")
    instructions = list(elf.disassemble(0x00403664))
    assert len(instructions) == 113411

    assert instructions[0] is not None
    assert instructions[0].to_string() == "0x403664: lui $gp, 0x9"
    assert instructions[113272] is not None
    assert instructions[113272].to_string() == "0x472044: mflo $10"

    assert isinstance(instructions[113272], lief.assembly.mips.Instruction)
    assert instructions[113272].opcode == lief.assembly.mips.OPCODE.MFLO


def test_mips_operands():
    elf = parse_elf("ELF/echo.mips_r3000.bin")
    instructions = list(elf.disassemble(0x00403664))

    # lui $gp, 0x9  ->  Register($gp), Immediate(0x9)
    inst_0 = instructions[0]
    assert isinstance(inst_0, lief.assembly.mips.Instruction)
    operands = list(inst_0.operands)
    assert len(operands) == 2

    assert isinstance(operands[0], lief.assembly.mips.operands.Register)
    assert operands[0].value == lief.assembly.mips.REG.GP

    assert isinstance(operands[1], lief.assembly.mips.operands.Immediate)
    assert operands[1].value == 0x9

    # sw $gp, 0x10($sp)  ->  Register($gp), Memory(base=$sp, offset=16)
    inst_4 = instructions[4]
    assert isinstance(inst_4, lief.assembly.mips.Instruction)
    operands = list(inst_4.operands)
    assert len(operands) == 2

    assert isinstance(operands[0], lief.assembly.mips.operands.Register)
    assert operands[0].value == lief.assembly.mips.REG.GP

    assert isinstance(operands[1], lief.assembly.mips.operands.Memory)
    assert operands[1].base == lief.assembly.mips.REG.SP
    assert operands[1].offset == 16
