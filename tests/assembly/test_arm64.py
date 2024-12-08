import lief
import pytest
from utils import get_sample

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

def _create_inst(elf: lief.ELF.Binary, addr: int,
                 asm: str) -> lief.assembly.aarch64.Instruction:
    return next(elf.disassemble_from_bytes(elf.assemble(addr, asm), addr))

def test_arm64e():
    macho = lief.MachO.parse(get_sample("MachO/ios17/DebugHierarchyKit")).at(0)

    instructions = list(macho.disassemble(0x00016650))
    assert len(instructions) == 276

    assert instructions[0].to_string() == "0x016650: adrp x17, #106496"
    assert isinstance(instructions[0], lief.assembly.aarch64.Instruction)
    assert instructions[0].opcode == lief.assembly.aarch64.OPCODE.ADRP
    new_inst = macho.assemble(0x016650, "adrp x17, #0x4000")
    assert new_inst.hex(":") == "31:00:00:90"
    assert next(macho.disassemble(0x016650)).to_string() == "0x016650: adrp x17, #16384"

    assert instructions[3].to_string() == "0x01665c: braa x16, x17"
    assert isinstance(instructions[3], lief.assembly.aarch64.Instruction)
    assert instructions[3].opcode == lief.assembly.aarch64.OPCODE.BRAA
    assert instructions[3].is_branch
    assert instructions[3].is_terminator

    new_inst = macho.assemble(0x01665c, "braa x18, x19")
    assert new_inst.hex(":") == "53:0a:1f:d7"
    assert next(macho.disassemble(0x01665c)).to_string() == "0x01665c: braa x18, x19"

def test_pe_arm64():
    pe = lief.PE.parse(get_sample("PE/elf_reader.arm64.pe.exe"))

    instructions = list(pe.disassemble(0x140001000))
    assert len(instructions) == 6245

    assert instructions[0].to_string() == "0x140001000: str x19, [sp, #-16]!"
    assert isinstance(instructions[0], lief.assembly.aarch64.Instruction)
    assert instructions[0].opcode == lief.assembly.aarch64.OPCODE.STRXpre

    assert instructions[4796].to_string() == "0x140005af0: ldr x30, [sp, #16]"
    assert isinstance(instructions[4796], lief.assembly.aarch64.Instruction)
    assert instructions[4796].opcode == lief.assembly.aarch64.OPCODE.LDRXui

def test_elf_arm64():
    elf = lief.ELF.parse(get_sample("ELF/issue_975_aarch64.o"))

    instructions = list(elf.disassemble_from_bytes(bytes(elf.get_section(".text").content)))
    assert len(instructions) == 12
    assert instructions[0].to_string() == "0x000000: bti c"
    assert instructions[10].to_string() == "0x000028: add sp, sp, #16"
    assert instructions[11].to_string() == "0x00002c: ret"

    elf = lief.ELF.parse(get_sample("ELF/libmonochrome-arm64.so"))

    instructions = list(elf.disassemble(0x056c19b4, 16))
    assert len(instructions) == 4
    assert instructions[0].to_string() == "0x56c19b4: paciasp"
    assert isinstance(instructions[0], lief.assembly.aarch64.Instruction)
    assert instructions[0].opcode == lief.assembly.aarch64.OPCODE.PACIASP

def test_arm64_operands():
    elf = lief.ELF.parse(get_sample("ELF/libmonochrome-arm64.so"))

    inst = _create_inst(elf, 0x18a5000, "mov x0, #1")
    operands = list(inst.operands)
    assert len(operands) == 3
    assert isinstance(operands[0], lief.assembly.aarch64.operands.Register)
    assert operands[0].value == lief.assembly.aarch64.REG.X0

    assert isinstance(operands[1], lief.assembly.aarch64.operands.Immediate)
    assert operands[1].value == 1

    inst = _create_inst(elf, 0x18a5000, "mrs x23, TPIDR_EL0")
    operands = list(inst.operands)
    assert len(operands) == 2
    assert isinstance(operands[0], lief.assembly.aarch64.operands.Register)
    assert operands[0].value == lief.assembly.aarch64.REG.X23

    assert isinstance(operands[1], lief.assembly.aarch64.operands.Register)
    assert operands[1].value == lief.assembly.aarch64.SYSREG.TPIDR_EL0

    inst = _create_inst(elf, 0x18a5000, "ldr x1, [x2, x3, lsl #3]")
    operands = list(inst.operands)
    assert len(operands) == 2
    assert isinstance(operands[0], lief.assembly.aarch64.operands.Register)
    assert operands[0].value == lief.assembly.aarch64.REG.X1

    assert isinstance(operands[1], lief.assembly.aarch64.operands.Memory)
    mem_info: lief.assembly.aarch64.operands.Memory = operands[1]
    assert mem_info.base == lief.assembly.aarch64.REG.X2
    assert mem_info.offset == lief.assembly.aarch64.REG.X3
    assert mem_info.shift.type == lief.assembly.aarch64.operands.Memory.SHIFT.LSL
    assert mem_info.shift.value == 3

    inst = _create_inst(elf, 0x18a5000, "str x3, [x2], #8")
    operands = list(inst.operands)
    assert len(operands) == 4
    assert isinstance(operands[0], lief.assembly.aarch64.operands.Register)
    assert operands[0].value == lief.assembly.aarch64.REG.X2

    assert isinstance(operands[1], lief.assembly.aarch64.operands.Register)
    assert operands[1].value == lief.assembly.aarch64.REG.X3

    assert isinstance(operands[2], lief.assembly.aarch64.operands.Memory)
    mem_info: lief.assembly.aarch64.operands.Memory = operands[2]
    assert mem_info.base == lief.assembly.aarch64.REG.X2
    assert mem_info.offset is None
    assert mem_info.shift.value == -1

    assert isinstance(operands[3], lief.assembly.aarch64.operands.Immediate)
    assert operands[3].value == 8

    inst = _create_inst(elf, 0x18a5000, "str x3, [x2, #8]")
    operands = list(inst.operands)
    assert len(operands) == 2

    assert isinstance(operands[0], lief.assembly.aarch64.operands.Register)
    assert operands[0].value == lief.assembly.aarch64.REG.X3

    assert isinstance(operands[1], lief.assembly.aarch64.operands.Memory)
    mem_info: lief.assembly.aarch64.operands.Memory = operands[1]
    assert mem_info.base == lief.assembly.aarch64.REG.X2
    assert mem_info.offset == 8

    inst = _create_inst(elf, 0x18a5000, "adrp x0, #0x1000")
    operands = list(inst.operands)
    assert len(operands) == 2

    assert isinstance(operands[0], lief.assembly.aarch64.operands.Register)
    assert operands[0].value == lief.assembly.aarch64.REG.X0

    assert isinstance(operands[1], lief.assembly.aarch64.operands.PCRelative)
    assert operands[1].value == 1
