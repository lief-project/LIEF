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


class Engine:
    pass

class Instruction:
    @property
    def address(self) -> int: ...

    @property
    def size(self) -> int: ...

    @property
    def mnemonic(self) -> str: ...

    def to_string(self) -> str: ...

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

    def __str__(self) -> str: ...
