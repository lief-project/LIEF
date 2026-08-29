from typing import Optional, Union

import lief.assembly.riscv

import lief.assembly.riscv


class Immediate(lief.assembly.riscv.Operand):
    __match_args__: tuple = ...

    @property
    def value(self) -> int: ...

class Register(lief.assembly.riscv.Operand):
    __match_args__: tuple = ...

    @property
    def value(self) -> Optional[Union[lief.assembly.riscv.REG, lief.assembly.riscv.SYSREG]]: ...

class Memory(lief.assembly.riscv.Operand):
    __match_args__: tuple = ...

    @property
    def base(self) -> lief.assembly.riscv.REG: ...

    @property
    def displacement(self) -> int: ...

class PCRelative(lief.assembly.riscv.Operand):
    __match_args__: tuple = ...

    @property
    def value(self) -> int: ...
