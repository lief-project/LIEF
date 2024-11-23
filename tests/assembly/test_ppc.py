import lief
import pytest
from utils import get_sample

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

def test_ppcbe():
    macho = lief.MachO.parse(get_sample("MachO/macho-issue-1110.bin")).at(0)
    instructions = list(macho.disassemble(0x00000b10))
    assert len(instructions) == 295

    assert instructions[0].to_string() == "0x000b10: mflr 0"
    assert instructions[121].to_string() == "0x000cf4: stmw 27, -20(1)"

    assert isinstance(instructions[121], lief.assembly.powerpc.Instruction)
    assert instructions[121].opcode == lief.assembly.powerpc.OPCODE.STMW
