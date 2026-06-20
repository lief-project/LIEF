import lief.assembly.riscv
from typing import Iterator, Optional, Union

import lief.assembly.riscv


class Immediate(lief.assembly.riscv.Operand):
    @property
    def value(self) -> int: ...

class Register(lief.assembly.riscv.Operand):
    @property
    def value(self) -> Optional[Union[lief.assembly.riscv.REG, lief.assembly.riscv.SYSREG]]: ...

class Memory(lief.assembly.riscv.Operand):
    @property
    def base(self) -> lief.assembly.riscv.REG: ...

    @property
    def displacement(self) -> int: ...

class PCRelative(lief.assembly.riscv.Operand):
    @property
    def value(self) -> int: ...
