import enum
import os
from typing import Iterator, Optional, Union, overload

from . import (
    editor as editor,
    parameters as parameters,
    types as types
)
import lief
import lief.assembly


def load(path: Union[str | os.PathLike]) -> Optional[DebugInfo]: ...

class Scope:
    class TYPE(enum.Enum):
        UNKNOWN = 0

        UNION = 1

        CLASS = 2

        STRUCT = 3

        NAMESPACE = 4

        FUNCTION = 5

        COMPILATION_UNIT = 6

    @property
    def name(self) -> str: ...

    @property
    def parent(self) -> Optional[Scope]: ...

    @property
    def type(self) -> Scope.TYPE: ...

    def chained(self, sep: str = '::') -> str: ...

class Type:
    class KIND(enum.Enum):
        UNKNOWN = 0

        UNSPECIFIED = 1

        BASE = 2

        CONST_KIND = 3

        CLASS = 4

        ARRAY = 5

        POINTER = 6

        STRUCT = 7

        UNION = 8

        TYPEDEF = 9

        REF = 10

        SET_TYPE = 11

        STRING = 12

        SUBROUTINE = 13

        POINTER_MEMBER = 14

        PACKED = 15

        FILE = 16

        THROWN = 17

        VOLATILE = 18

        RESTRICT = 19

        INTERFACE = 20

        SHARED = 21

        RVALREF = 22

        TEMPLATE_ALIAS = 23

        COARRAY = 24

        DYNAMIC = 25

        ATOMIC = 26

        IMMUTABLE = 27

        ENUM = 28

    @property
    def kind(self) -> Type.KIND: ...

    @property
    def name(self) -> Optional[str]: ...

    @property
    def size(self) -> Optional[int]: ...

    @property
    def location(self) -> lief.debug_location_t: ...

    @property
    def is_unspecified(self) -> bool: ...

    @property
    def scope(self) -> Optional[Scope]: ...

class Variable:
    @property
    def name(self) -> str: ...

    @property
    def linkage_name(self) -> str: ...

    @property
    def address(self) -> Optional[int]: ...

    @property
    def size(self) -> Optional[int]: ...

    @property
    def is_constexpr(self) -> bool: ...

    @property
    def debug_location(self) -> lief.debug_location_t: ...

    @property
    def type(self) -> Optional[Type]: ...

    @property
    def scope(self) -> Optional[Scope]: ...

class Function:
    @property
    def name(self) -> str: ...

    @property
    def linkage_name(self) -> str: ...

    @property
    def address(self) -> Optional[int]: ...

    @property
    def variables(self) -> Iterator[Optional[Variable]]: ...

    @property
    def is_artificial(self) -> bool: ...

    @property
    def is_external(self) -> bool: ...

    @property
    def size(self) -> int: ...

    @property
    def ranges(self) -> list[lief.range_t]: ...

    @property
    def debug_location(self) -> lief.debug_location_t: ...

    @property
    def type(self) -> Optional[Type]: ...

    @property
    def parameters(self) -> list[Optional[Parameter]]: ...

    @property
    def thrown_types(self) -> list[Optional[Type]]: ...

    @property
    def scope(self) -> Optional[Scope]: ...

    @property
    def instructions(self) -> Iterator[Optional[lief.assembly.Instruction]]: ...

class Parameter:
    @property
    def name(self) -> str: ...

    @property
    def type(self) -> Optional[Type]: ...

class CompilationUnit:
    class Language:
        class LANG(enum.Enum):
            @staticmethod
            def from_value(arg: int, /) -> CompilationUnit.Language.LANG: ...

            def __eq__(self, arg, /) -> bool: ...

            def __ne__(self, arg, /) -> bool: ...

            def __int__(self) -> int: ...

            UNKNOWN = 0

            C = 1

            CPP = 2

            RUST = 3

            DART = 4

            MODULA = 5

            FORTRAN = 6

            SWIFT = 7

            D = 8

            JAVA = 9

            COBOL = 10

        lang: CompilationUnit.Language.LANG

        version: int

    @property
    def name(self) -> str: ...

    @property
    def producer(self) -> str: ...

    @property
    def compilation_dir(self) -> str: ...

    @property
    def language(self) -> CompilationUnit.Language: ...

    @property
    def low_address(self) -> int: ...

    @property
    def high_address(self) -> int: ...

    @property
    def size(self) -> int: ...

    @property
    def ranges(self) -> list[lief.range_t]: ...

    @overload
    def find_function(self, name: str) -> Optional[Function]: ...

    @overload
    def find_function(self, addr: int) -> Optional[Function]: ...

    @overload
    def find_variable(self, addr: int) -> Optional[Variable]: ...

    @overload
    def find_variable(self, name: str) -> Optional[Variable]: ...

    @property
    def types(self) -> Iterator[Optional[Type]]: ...

    @property
    def functions(self) -> Iterator[Optional[Function]]: ...

    @property
    def imported_functions(self) -> Iterator[Optional[Function]]: ...

    @property
    def variables(self) -> Iterator[Optional[Variable]]: ...

class DebugInfo(lief.DebugInfo):
    @overload
    def find_function(self, name: str) -> Optional[Function]: ...

    @overload
    def find_function(self, addr: int) -> Optional[Function]: ...

    @overload
    def find_variable(self, addr: int) -> Optional[Variable]: ...

    @overload
    def find_variable(self, name: str) -> Optional[Variable]: ...

    def find_type(self, name: str) -> Optional[Type]: ...

    @property
    def compilation_units(self) -> Iterator[Optional[CompilationUnit]]: ...

class Editor:
    @staticmethod
    def from_binary(bin: lief.Binary) -> Optional[Editor]: ...

    def create_compilation_unit(self) -> Optional[editor.CompilationUnit]: ...

    def write(self, output: Union[str | os.PathLike]) -> None: ...
