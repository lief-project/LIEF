import lief
import pytest
from utils import parse_elf

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)


def test_simple_bpf():
    elf = parse_elf("ELF/hello.bpf.o")
    section = elf.get_section("tp/syscalls/sys_enter_write")
    assert section is not None
    instructions = list(elf.disassemble_from_bytes(bytes(section.content)))

    assert len(instructions) == 21
    assert instructions[0] is not None
    assert instructions[0].to_string() == "0x000000: call 0xe"
    assert isinstance(instructions[0], lief.assembly.ebpf.Instruction)
    assert instructions[0].opcode == lief.assembly.ebpf.OPCODE.JAL
    assert instructions[19] is not None
    assert instructions[19].to_string() == "0x0000c0: r0 = 0x0"


def test_bpf_operands():
    elf = parse_elf("ELF/hello.bpf.o")
    section = elf.get_section("tp/syscalls/sys_enter_write")
    assert section is not None
    instructions = list(elf.disassemble_from_bytes(bytes(section.content)))

    # *(u32 *)(r10 - 0x8) = r1  ->  Register(r1), Memory(base=r10, disp=-8)
    inst_2 = instructions[2]
    assert isinstance(inst_2, lief.assembly.ebpf.Instruction)
    operands = list(inst_2.operands)
    assert len(operands) == 2

    assert isinstance(operands[0], lief.assembly.ebpf.operands.Register)
    assert operands[0].value == lief.assembly.ebpf.REG.R1

    assert isinstance(operands[1], lief.assembly.ebpf.operands.Memory)
    assert operands[1].base == lief.assembly.ebpf.REG.R10
    assert operands[1].displacement == -8

    # r0 = 0x0  ->  Register(r0), Immediate(0x0)
    inst_19 = instructions[19]
    assert isinstance(inst_19, lief.assembly.ebpf.Instruction)
    operands = list(inst_19.operands)
    assert len(operands) == 2

    assert isinstance(operands[0], lief.assembly.ebpf.operands.Register)
    assert operands[0].value == lief.assembly.ebpf.REG.R0

    assert isinstance(operands[1], lief.assembly.ebpf.operands.Immediate)
    assert operands[1].value == 0x0
