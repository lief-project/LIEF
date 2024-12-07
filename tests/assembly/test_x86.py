import lief
import pytest
from utils import get_sample

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

def test_pe_x86():
    pe = lief.PE.parse(get_sample("PE/PE32_x86_binary_cmd-upx.exe"))

    upx1 = pe.get_section("UPX1")
    delta = 0x4ad4ee70 - 0x4ad3c000
    buffer =  bytes(upx1.content)[delta:]

    instructions = list(pe.disassemble_from_bytes(buffer, 0x4ad4ee70))

    assert len(instructions) == 419
    assert instructions[0].to_string() == "0x4ad4ee70: pushal"
    assert isinstance(instructions[0], lief.assembly.x86.Instruction)
    assert instructions[0].opcode == lief.assembly.x86.OPCODE.PUSHA32

    assert instructions[5].to_string() == "0x4ad4ee7f: nop"
    assert instructions[5].raw.hex(":") == "90"
    assert instructions[5].size == 1

def test_pe_x86_64():
    pe = lief.PE.parse(get_sample("PE/ntoskrnl.exe"))
    instructions = list(pe.disassemble(0x140200000))

    assert len(instructions) == 54785
    assert instructions[0].to_string() == "0x140200000: int3"
    assert instructions[8].to_string() == "0x140200008: mov rax, rsp"
    assert isinstance(instructions[8], lief.assembly.x86.Instruction)
    assert instructions[8].opcode == lief.assembly.x86.OPCODE.MOV64rr_REV

def test_elf_x86():
    elf = lief.ELF.parse(get_sample("ELF/ELF32_x86_library_libshellx.so"))

    instructions = list(elf.disassemble(0x000010c0))

    assert len(instructions) == 822
    assert instructions[0].to_string() == "0x0010c0: push ebp"

def test_elf_x86_64():
    elf = lief.ELF.parse(get_sample("ELF/ELF64_x86-64_binary_static-binary.bin"))
    instructions = list(elf.disassemble(0x00400cdd))
    assert len(instructions) == 139591

    assert instructions[0].to_string() == "0x400cdd: push rax"
    assert instructions[83418].to_string() == "0x453df1: vmovdqu xmm1, xmmword ptr [rdi]"

def test_macho_x86():
    macho = lief.MachO.parse(get_sample("MachO/FAT_MachO_x86_x86-64_library_libdyld.dylib")).take(lief.MachO.Header.CPU_TYPE.X86)

    instructions = list(macho.disassemble(0x1141))

    for idx, inst in enumerate(instructions):
        print(idx, inst)

    assert len(instructions) == 6946
    assert instructions[0].to_string() == "0x001141: push ebp"
    assert instructions[9].to_string() == "0x00115a: inc dword ptr [esi + 20669]"


def test_macho_x86_64():
    macho = lief.MachO.parse(get_sample("MachO/FAT_MachO_x86_x86-64_library_libdyld.dylib")).take(lief.MachO.Header.CPU_TYPE.X86_64)

    instructions = list(macho.disassemble(0x00001108))

    for idx, inst in enumerate(instructions):
        print(idx, inst)

    assert len(instructions) == 4903
    assert instructions[0].to_string() == "0x001108: push rbp"
    assert instructions[23].to_string() == "0x001154: dec dword ptr [rip + 21174]"

def test_x86_operands():
    pe = lief.PE.parse(get_sample("PE/ntoskrnl.exe"))
    instructions = list(pe.disassemble(0x140200000))

    # -------------------------------------------------------------------------

    operands = list(instructions[8].operands)

    assert len(operands) == 2
    assert isinstance(operands[0], lief.assembly.x86.operands.Register)
    assert isinstance(operands[1], lief.assembly.x86.operands.Register)
    assert operands[0].value == lief.assembly.x86.REG.RAX
    assert operands[1].value == lief.assembly.x86.REG.RSP

    # -------------------------------------------------------------------------

    operands = list(instructions[9].operands)

    assert len(operands) == 2
    assert isinstance(operands[0], lief.assembly.x86.operands.Memory)
    assert operands[0].base == lief.assembly.x86.REG.RAX
    assert operands[0].scaled_register == lief.assembly.x86.REG.NoRegister
    assert operands[0].scale == 1
    assert operands[0].displacement == 8

    # -------------------------------------------------------------------------

    operands = list(instructions[21].operands)

    assert len(operands) == 1
    assert isinstance(operands[0], lief.assembly.x86.operands.PCRelative)
    assert operands[0].value == 0x26889d

    # -------------------------------------------------------------------------

    operands = list(instructions[53].operands)

    assert len(operands) == 2
    assert isinstance(operands[1], lief.assembly.x86.operands.Immediate)
    assert operands[1].value == -33

def test_x86_semnatic_info():
    pe = lief.PE.parse(get_sample("PE/ntoskrnl.exe"))
    inst = next(pe.disassemble_from_bytes(pe.assemble(0x140200000, "syscall")))
    assert inst.is_syscall

    inst = next(pe.disassemble_from_bytes(pe.assemble(0x140200000, "call _foo")))
    assert inst.is_call
    assert not inst.is_terminator
    assert str(next(inst.operands)) == "PCRel=0x0"

    inst = next(pe.disassemble_from_bytes(pe.assemble(0x140200000, "jmp rax")))
    assert inst.is_branch
    assert inst.is_barrier
    assert inst.is_indirect_branch

    inst = next(pe.disassemble_from_bytes(pe.assemble(0x140200000, "vmovdqu xmm1, xmmword ptr [rdi]")))
    assert inst.is_memory_access
    assert inst.memory_access == lief.assembly.Instruction.MemoryAccess.READ

    inst = next(pe.disassemble_from_bytes(pe.assemble(0x140200000, "mov rax, rbx")))
    assert inst.is_move_reg

    inst = next(pe.disassemble_from_bytes(pe.assemble(0x140200000, "add rax, rbx")))
    assert inst.is_add

    inst = next(pe.disassemble_from_bytes(pe.assemble(0x140200000, "ud1 rax, rax")))
    assert inst.is_trap

    inst = next(pe.disassemble_from_bytes(pe.assemble(0x140200000, "ret")))
    assert inst.is_return

    inst = next(pe.disassemble_from_bytes(b"\x75\x07"))
    assert inst.is_conditional_branch

    inst = next(pe.disassemble_from_bytes(b"\xeb\x10"))
    assert inst.is_unconditional_branch
    assert inst.branch_target == 18

    inst = next(pe.disassemble_from_bytes(pe.assemble(0x140200000, "cmp rax, rbx")))
    assert inst.is_compare

    inst = next(pe.disassemble_from_bytes(pe.assemble(0x140200000, "mov rax, 123")))
    assert inst.is_move_immediate

    inst = next(pe.disassemble_from_bytes(pe.assemble(0x140200000, "movq mm1, mm2")))
    assert inst.is_bitcast
