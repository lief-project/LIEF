import lief
import pytest
from utils import parse_macho

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)


def test_ppcbe():
    macho = parse_macho("MachO/macho-issue-1110.bin").at(0)
    assert macho is not None
    instructions = list(macho.disassemble(0x00000B10))
    assert len(instructions) == 295

    assert instructions[0] is not None
    assert instructions[0].to_string() == "0x000b10: mflr 0"
    assert instructions[121] is not None
    assert instructions[121].to_string() == "0x000cf4: stmw 27, -20(1)"

    assert isinstance(instructions[121], lief.assembly.powerpc.Instruction)
    assert instructions[121].opcode == lief.assembly.powerpc.OPCODE.STMW


def test_ppc_operands():
    macho = parse_macho("MachO/macho-issue-1110.bin").at(0)
    assert macho is not None
    instructions = list(macho.disassemble(0x00000B10))

    # stmw 27, -20(1)  ->  Register(27), Memory(base=1, offset=-20)
    inst = instructions[121]
    assert isinstance(inst, lief.assembly.powerpc.Instruction)
    operands = list(inst.operands)
    assert len(operands) == 2

    assert isinstance(operands[0], lief.assembly.powerpc.operands.Register)
    assert operands[0].value == lief.assembly.powerpc.REG.R27

    assert isinstance(operands[1], lief.assembly.powerpc.operands.Memory)
    assert operands[1].base == lief.assembly.powerpc.REG.R1
    assert operands[1].offset == -20
