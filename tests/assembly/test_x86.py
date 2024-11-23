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
