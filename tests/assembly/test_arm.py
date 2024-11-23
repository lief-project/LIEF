import lief
import pytest
from utils import get_sample

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

def test_arm_thumb():
    elf = lief.ELF.parse(get_sample("ELF/libmonochrome-armv7.so"))
    instructions = list(elf.disassemble("Java_J_N_MENF59pO"))
    assert len(instructions) == 181

    assert instructions[0].to_string() == "0x468b700: push.w {r4, r5, r6, r7, r8, r9, lr}"
    assert instructions[1].to_string() == "0x468b704: sub sp, #76"
    assert instructions[8].to_string() == "0x468b712: strd r0, r0, [sp, #64]"

    assert isinstance(instructions[8], lief.assembly.arm.Instruction)
    assert instructions[8].opcode == lief.assembly.arm.OPCODE.t2STRDi8

def test_arm():
    macho = lief.MachO.parse(get_sample("MachO/MachO32_ARM_binary_data-in-code-LLVM.bin")).at(0)
    instructions = list(macho.disassemble(0))
    assert len(instructions) == 2

    assert instructions[0].to_string() == "0x000000: andeq r0, r0, r10"
    assert instructions[1].to_string() == "0x000004: andeq r0, r0, r1"

    assert isinstance(instructions[1], lief.assembly.arm.Instruction)
    assert instructions[1].opcode == lief.assembly.arm.OPCODE.ANDrr
