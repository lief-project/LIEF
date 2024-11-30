import lief
import pytest
from utils import get_sample

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

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
