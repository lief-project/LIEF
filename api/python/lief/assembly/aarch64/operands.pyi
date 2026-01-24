import enum
import lief.assembly.aarch64
from typing import Iterator, Optional, Union

import lief.assembly.aarch64


class Immediate(lief.assembly.aarch64.Operand):
    @property
    def value(self) -> int: ...

class Register(lief.assembly.aarch64.Operand):
    @property
    def value(self) -> Optional[Union[lief.assembly.aarch64.REG, lief.assembly.aarch64.SYSREG]]: ...

class Memory(lief.assembly.aarch64.Operand):
    class SHIFT(enum.Enum):
        UNKNOWN = 0

        LSL = 1

        UXTX = 2

        UXTW = 3

        SXTX = 4

        SXTW = 5

    class shift_info_t:
        @property
        def type(self) -> Memory.SHIFT: ...

        @property
        def value(self) -> int: ...

    @property
    def base(self) -> lief.assembly.aarch64.REG: ...

    @property
    def offset(self) -> Optional[Union[lief.assembly.aarch64.REG, int]]: ...

    @property
    def shift(self) -> Memory.shift_info_t: ...

class PCRelative(lief.assembly.aarch64.Operand):
    @property
    def value(self) -> int: ...
