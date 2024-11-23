import lief
import pytest
from utils import get_sample

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

def test_mipsr3000():
    elf = lief.ELF.parse(get_sample("ELF/echo.mips_r3000.bin"))
    instructions = list(elf.disassemble(0x00403664))
    assert len(instructions) == 113411

    assert instructions[0].to_string() == "0x403664: lui $gp, 9"
    assert instructions[113272].to_string() == "0x472044: mflo $10"

    assert isinstance(instructions[113272], lief.assembly.mips.Instruction)
    assert instructions[113272].opcode == lief.assembly.mips.OPCODE.MFLO
