from typing import Iterator, Optional, Union

import lief


class Alloc(Code):
    @property
    def size(self) -> int: ...

class Code:
    @property
    def opcode(self) -> lief.PE.RuntimeFunctionX64.UNWIND_OPCODES: ...

    @property
    def position(self) -> int: ...

    def __str__(self) -> str: ...

class Epilog(Code):
    @property
    def flags(self) -> int: ...

    @property
    def size(self) -> int: ...

class PushMachFrame(Code):
    @property
    def value(self) -> int: ...

class PushNonVol(Code):
    @property
    def reg(self) -> lief.PE.RuntimeFunctionX64.UNWIND_REG: ...

class SaveNonVolatile(Code):
    @property
    def reg(self) -> lief.PE.RuntimeFunctionX64.UNWIND_REG: ...

    @property
    def offset(self) -> int: ...

class SaveXMM128(Code):
    @property
    def num(self) -> int: ...

    @property
    def offset(self) -> int: ...

class SetFPReg(Code):
    @property
    def reg(self) -> lief.PE.RuntimeFunctionX64.UNWIND_REG: ...

class Spare(Code):
    pass
