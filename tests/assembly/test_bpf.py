import lief
import pytest
from utils import get_sample

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

def test_simple_bpf():
    elf = lief.ELF.parse(get_sample("ELF/hello.bpf.o"))
    instructions = list(elf.disassemble_from_bytes(bytes(elf.get_section("tp/syscalls/sys_enter_write").content)))

    assert len(instructions) == 21
    assert instructions[0].to_string() == "0x000000: call 14"
    assert isinstance(instructions[0], lief.assembly.ebpf.Instruction)
    assert instructions[0].opcode == lief.assembly.ebpf.OPCODE.JAL
    assert instructions[19].to_string() == "0x0000c0: r0 = 0"
