import enum
from typing import Iterator, Optional, Union

from . import (
    aarch64 as aarch64,
    arm as arm,
    ebpf as ebpf,
    mips as mips,
    powerpc as powerpc,
    riscv as riscv,
    x86 as x86
)
import lief


class Engine:
    pass

class Instruction:
    class MemoryAccess(enum.Flag):
        @staticmethod
        def from_value(arg: int, /) -> Instruction.MemoryAccess: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        NONE = 0

        READ = 1

        WRITE = 2

    @property
    def address(self) -> int: ...

    @property
    def size(self) -> int: ...

    @property
    def mnemonic(self) -> str: ...

    def to_string(self, with_address: bool = True) -> str: ...

    @property
    def raw(self) -> bytes: ...

    @property
    def is_call(self) -> bool: ...

    @property
    def is_terminator(self) -> bool: ...

    @property
    def is_branch(self) -> bool: ...

    @property
    def is_syscall(self) -> bool: ...

    @property
    def is_memory_access(self) -> bool: ...

    @property
    def is_move_reg(self) -> bool: ...

    @property
    def is_add(self) -> bool: ...

    @property
    def is_trap(self) -> bool: ...

    @property
    def is_barrier(self) -> bool: ...

    @property
    def is_return(self) -> bool: ...

    @property
    def is_indirect_branch(self) -> bool: ...

    @property
    def is_conditional_branch(self) -> bool: ...

    @property
    def is_unconditional_branch(self) -> bool: ...

    @property
    def is_compare(self) -> bool: ...

    @property
    def is_move_immediate(self) -> bool: ...

    @property
    def is_bitcast(self) -> bool: ...

    @property
    def memory_access(self) -> Instruction.MemoryAccess: ...

    @property
    def branch_target(self) -> Union[int, lief.lief_errors]: ...

    def __str__(self) -> str: ...
