import enum
from typing import Iterator, Optional, Union

from . import types as types
import lief


class CompilationUnit:
    @property
    def module_name(self) -> str: ...

    @property
    def object_filename(self) -> str: ...

    @property
    def sources(self) -> Iterator[str]: ...

    @property
    def functions(self) -> Iterator[Optional[Function]]: ...

class DebugInfo(lief.DebugInfo):
    @property
    def age(self) -> int: ...

    @property
    def guid(self) -> str: ...

    @staticmethod
    def from_file(filepath: str) -> Optional[DebugInfo]: ...

    def find_type(self, name: str) -> Optional[Type]: ...

    def find_public_symbol(self, name: str) -> Optional[PublicSymbol]: ...

    @property
    def public_symbols(self) -> Iterator[Optional[PublicSymbol]]: ...

    @property
    def compilation_units(self) -> Iterator[Optional[CompilationUnit]]: ...

    @property
    def types(self) -> Iterator[Optional[Type]]: ...

class Function:
    @property
    def name(self) -> str: ...

    @property
    def RVA(self) -> int: ...

    @property
    def code_size(self) -> int: ...

    @property
    def section_name(self) -> str: ...

    @property
    def debug_location(self) -> lief.debug_location_t: ...

class PublicSymbol:
    @property
    def name(self) -> str: ...

    @property
    def section_name(self) -> str: ...

    @property
    def RVA(self) -> int: ...

    @property
    def demangled_name(self) -> str: ...

class Type:
    class KIND(enum.Enum):
        UNKNOWN = 0

        CLASS = 1

        POINTER = 2

        SIMPLE = 3

        ENUM = 4

        FUNCTION = 5

        MODIFIER = 6

        BITFIELD = 7

        ARRAY = 8

        UNION = 9

        STRUCTURE = 10

        INTERFACE = 11

    @property
    def kind(self) -> Type.KIND: ...

def load(path: str) -> Optional[DebugInfo]: ...
