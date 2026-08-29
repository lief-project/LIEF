import lief
import pytest
from utils import parse_elf, parse_macho, parse_pe

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)


def test_pe_x86():
    pe = parse_pe("PE/PE32_x86_binary_cmd-upx.exe")

    upx1 = pe.get_section("UPX1")
    assert upx1 is not None
    delta = 0x4AD4EE70 - 0x4AD3C000
    buffer = bytes(upx1.content)[delta:]

    instructions = list(pe.disassemble_from_bytes(buffer, 0x4AD4EE70))

    assert len(instructions) == 419
    assert instructions[0] is not None
    assert instructions[0].to_string() == "0x4ad4ee70: pushal"
    assert isinstance(instructions[0], lief.assembly.x86.Instruction)
    assert instructions[0].opcode == lief.assembly.x86.OPCODE.PUSHA32

    assert instructions[5] is not None
    assert instructions[5].to_string() == "0x4ad4ee7f: nop"
    assert instructions[5].raw.hex(":") == "90"
    assert instructions[5].size == 1


def test_pe_x86_64():
    pe = parse_pe("PE/ntoskrnl.exe")
    instructions = list(pe.disassemble(0x140200000))

    assert len(instructions) == 54382
    assert instructions[0] is not None
    assert instructions[0].to_string() == "0x140200000: int3"
    assert instructions[8] is not None
    assert instructions[8].to_string() == "0x140200008: mov rax, rsp"
    assert isinstance(instructions[8], lief.assembly.x86.Instruction)
    assert instructions[8].opcode == lief.assembly.x86.OPCODE.MOV64rr_REV


def test_elf_x86():
    elf = parse_elf("ELF/ELF32_x86_library_libshellx.so")

    instructions = list(elf.disassemble(0x000010C0))

    assert len(instructions) == 821
    assert instructions[0] is not None
    assert instructions[0].to_string() == "0x0010c0: push ebp"


def test_elf_x86_64():
    elf = parse_elf("ELF/ELF64_x86-64_binary_static-binary.bin")
    instructions = list(elf.disassemble(0x00400CDD))
    assert len(instructions) == 139400

    assert instructions[0] is not None
    assert instructions[0].to_string() == "0x400cdd: push rax"
    assert instructions[83276] is not None
    assert (
        instructions[83276].to_string() == "0x453df1: vmovdqu xmm1, xmmword ptr [rdi]"
    )


def test_macho_x86():
    macho = parse_macho("MachO/FAT_MachO_x86_x86-64_library_libdyld.dylib").take(
        lief.MachO.Header.CPU_TYPE.X86
    )
    assert macho is not None

    instructions = list(macho.disassemble(0x1141))

    for idx, inst in enumerate(instructions):
        lief.logging.info(f"{idx} {inst}")

    assert len(instructions) == 6943
    assert instructions[0] is not None
    assert instructions[0].to_string() == "0x001141: push ebp"
    assert instructions[9] is not None
    assert instructions[9].to_string() == "0x00115a: inc dword ptr [esi + 0x50bd]"


def test_macho_x86_64():
    macho = parse_macho("MachO/FAT_MachO_x86_x86-64_library_libdyld.dylib").take(
        lief.MachO.Header.CPU_TYPE.X86_64
    )
    assert macho is not None

    instructions = list(macho.disassemble(0x00001108))

    for idx, inst in enumerate(instructions):
        lief.logging.info(f"{idx} {inst}")

    assert len(instructions) == 4900
    assert instructions[0] is not None
    assert instructions[0].to_string() == "0x001108: push rbp"
    assert instructions[23] is not None
    assert instructions[23].to_string() == "0x001154: dec dword ptr [rip + 0x52b6]"


def test_x86_operands():
    pe = parse_pe("PE/ntoskrnl.exe")
    instructions = list(pe.disassemble(0x140200000))

    # -------------------------------------------------------------------------

    assert instructions[8] is not None
    assert isinstance(instructions[8], lief.assembly.x86.Instruction)
    operands = list(instructions[8].operands)

    assert len(operands) == 2
    assert isinstance(operands[0], lief.assembly.x86.operands.Register)
    assert isinstance(operands[1], lief.assembly.x86.operands.Register)
    assert operands[0].value == lief.assembly.x86.REG.RAX
    assert operands[1].value == lief.assembly.x86.REG.RSP

    # -------------------------------------------------------------------------

    assert instructions[9] is not None
    assert isinstance(instructions[9], lief.assembly.x86.Instruction)
    operands = list(instructions[9].operands)

    assert len(operands) == 2
    assert isinstance(operands[0], lief.assembly.x86.operands.Memory)
    assert operands[0].base == lief.assembly.x86.REG.RAX
    assert operands[0].scaled_register == lief.assembly.x86.REG.NoRegister
    assert operands[0].scale == 1
    assert operands[0].displacement == 8

    # -------------------------------------------------------------------------

    assert instructions[20] is not None
    assert isinstance(instructions[20], lief.assembly.x86.Instruction)
    operands = list(instructions[20].operands)

    assert len(operands) == 1
    assert isinstance(operands[0], lief.assembly.x86.operands.PCRelative)
    assert operands[0].value == 0x26889D

    # -------------------------------------------------------------------------

    assert instructions[51] is not None
    assert isinstance(instructions[51], lief.assembly.x86.Instruction)
    operands = list(instructions[51].operands)

    assert len(operands) == 2
    assert isinstance(operands[1], lief.assembly.x86.operands.Immediate)
    assert operands[1].value == -33


def test_x86_semnatic_info():
    pe = parse_pe("PE/ntoskrnl.exe")
    inst = next(pe.disassemble_from_bytes(pe.assemble(0x140200000, "syscall")))
    assert inst is not None
    assert inst.is_syscall

    inst = next(pe.disassemble_from_bytes(pe.assemble(0x140200000, "call _foo")))
    assert inst is not None
    assert inst.is_call
    assert not inst.is_terminator
    assert isinstance(inst, lief.assembly.x86.Instruction)
    assert str(next(inst.operands)) == "PCRel=0x0"

    inst = next(pe.disassemble_from_bytes(pe.assemble(0x140200000, "jmp rax")))
    assert inst is not None
    assert inst.is_branch
    assert inst.is_barrier
    assert inst.is_indirect_branch

    inst = next(
        pe.disassemble_from_bytes(
            pe.assemble(0x140200000, "vmovdqu xmm1, xmmword ptr [rdi]")
        )
    )
    assert inst is not None
    assert inst.is_memory_access
    assert inst.memory_access == lief.assembly.Instruction.MemoryAccess.READ

    inst = next(pe.disassemble_from_bytes(pe.assemble(0x140200000, "mov rax, rbx")))
    assert inst is not None
    assert inst.is_move_reg

    inst = next(pe.disassemble_from_bytes(pe.assemble(0x140200000, "add rax, rbx")))
    assert inst is not None
    assert inst.is_add

    inst = next(pe.disassemble_from_bytes(pe.assemble(0x140200000, "ud1 rax, rax")))
    assert inst is not None
    assert inst.is_trap

    inst = next(pe.disassemble_from_bytes(pe.assemble(0x140200000, "ret")))
    assert inst is not None
    assert inst.is_return

    inst = next(pe.disassemble_from_bytes(b"\x75\x07"))
    assert inst is not None
    assert inst.is_conditional_branch

    inst = next(pe.disassemble_from_bytes(b"\xeb\x10"))
    assert inst is not None
    assert inst.is_unconditional_branch
    assert inst.branch_target == 18

    inst = next(pe.disassemble_from_bytes(pe.assemble(0x140200000, "cmp rax, rbx")))
    assert inst is not None
    assert inst.is_compare

    inst = next(pe.disassemble_from_bytes(pe.assemble(0x140200000, "mov rax, 123")))
    assert inst is not None
    assert inst.is_move_immediate

    inst = next(pe.disassemble_from_bytes(pe.assemble(0x140200000, "movq mm1, mm2")))
    assert inst is not None
    assert inst.is_bitcast


def test_x86_lock_prefix():
    pe = parse_pe("PE/ntoskrnl.exe")

    def disassemble(asm: str) -> lief.assembly.x86.Instruction:
        inst = next(
            pe.disassemble_from_bytes(pe.assemble(0x140200000, asm), 0x140200000)
        )
        assert isinstance(inst, lief.assembly.x86.Instruction)
        return inst

    inst = disassemble("add dword ptr [rax], ebx")
    assert not inst.has_lock_prefix
    assert inst.is_lockable
    assert not inst.is_atomic

    locked = inst.lock()
    assert locked is not None
    assert isinstance(locked, lief.assembly.x86.Instruction)
    assert locked.has_lock_prefix
    assert locked.is_atomic
    assert locked.to_string() == "0x140200000: lock add dword ptr [rax], ebx"
    assert bytes(locked.raw) == b"\xf0\x01\x18"

    unlocked = inst.unlock()
    assert unlocked is not None
    assert not unlocked.has_lock_prefix
    assert bytes(unlocked.raw) == bytes(inst.raw)

    inst = next(pe.disassemble_from_bytes(b"\xf0\x01\x18", 0x140200000))
    assert inst is not None
    assert isinstance(inst, lief.assembly.x86.Instruction)
    assert inst.to_string() == "0x140200000: lock add dword ptr [rax], ebx"
    assert inst.has_lock_prefix
    assert inst.is_lockable
    assert inst.is_atomic

    relocked = inst.lock()
    assert relocked is not None
    assert relocked.has_lock_prefix
    assert bytes(relocked.raw) == bytes(inst.raw)

    unlocked = inst.unlock()
    assert unlocked is not None
    assert not unlocked.has_lock_prefix
    assert not unlocked.is_atomic
    assert unlocked.to_string() == "0x140200000: add dword ptr [rax], ebx"
    assert bytes(unlocked.raw) == b"\x01\x18"

    inst = disassemble("xchg dword ptr [rax], ebx")
    assert not inst.has_lock_prefix
    assert inst.is_lockable
    assert inst.is_atomic

    inst = disassemble("xchg ebx, ecx")
    assert not inst.has_lock_prefix
    assert not inst.is_lockable
    assert not inst.is_atomic
    assert inst.lock() is None

    inst = disassemble("cmpxchg qword ptr [rdi], rcx")
    assert not inst.has_lock_prefix
    assert inst.is_lockable
    assert not inst.is_atomic

    locked = inst.lock()
    assert locked is not None
    assert locked.is_atomic
    assert bytes(locked.raw) == b"\xf0\x48\x0f\xb1\x0f"

    inst = disassemble("mov rax, rbx")
    assert not inst.has_lock_prefix
    assert not inst.is_lockable
    assert not inst.is_atomic
    assert inst.lock() is None
