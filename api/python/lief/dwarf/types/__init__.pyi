import enum
from typing import Iterator, Optional, Union as _Union

import lief


class Array(lief.dwarf.Type):
    class size_info_t:
        @property
        def type(self) -> lief.dwarf.Type: ...

        @property
        def name(self) -> str: ...

        @property
        def size(self) -> int: ...

    @property
    def underlying_type(self) -> lief.dwarf.Type: ...

    @property
    def size_info(self) -> Array.size_info_t: ...

class Atomic(lief.dwarf.Type):
    @property
    def underlying_type(self) -> lief.dwarf.Type: ...

class Base(lief.dwarf.Type):
    class ENCODING(enum.Enum):
        NONE = 0

        SIGNED = 1

        SIGNED_CHAR = 2

        UNSIGNED = 3

        UNSIGNED_CHAR = 4

        FLOAT = 5

        BOOLEAN = 6

        ADDRESS = 7

    @property
    def encoding(self) -> Base.ENCODING: ...

class Class(ClassLike):
    pass

class ClassLike(lief.dwarf.Type):
    class Member:
        @property
        def name(self) -> str: ...

        @property
        def type(self) -> Optional[lief.dwarf.Type]: ...

        @property
        def is_external(self) -> bool: ...

        @property
        def is_declaration(self) -> bool: ...

        @property
        def offset(self) -> Optional[int]: ...

        @property
        def bit_offset(self) -> Optional[int]: ...

    @property
    def members(self) -> list[ClassLike.Member]: ...

    def find_member(self, offset: int) -> Optional[ClassLike.Member]: ...

    @property
    def functions(self) -> Iterator[Optional[lief.dwarf.Function]]: ...

class Coarray(lief.dwarf.Type):
    pass

class Const(lief.dwarf.Type):
    @property
    def underlying_type(self) -> lief.dwarf.Type: ...

class Dynamic(lief.dwarf.Type):
    pass

class Enum(lief.dwarf.Type):
    pass

class File(lief.dwarf.Type):
    pass

class Immutable(lief.dwarf.Type):
    @property
    def underlying_type(self) -> lief.dwarf.Type: ...

class Interface(lief.dwarf.Type):
    pass

class Packed(ClassLike):
    pass

class Pointer(lief.dwarf.Type):
    @property
    def underlying_type(self) -> lief.dwarf.Type: ...

class PointerToMember(lief.dwarf.Type):
    @property
    def underlying_type(self) -> lief.dwarf.Type: ...

    @property
    def containing_type(self) -> Optional[lief.dwarf.Type]: ...

class RValueReference(lief.dwarf.Type):
    @property
    def underlying_type(self) -> lief.dwarf.Type: ...

class Reference(lief.dwarf.Type):
    @property
    def underlying_type(self) -> lief.dwarf.Type: ...

class Restrict(lief.dwarf.Type):
    @property
    def underlying_type(self) -> lief.dwarf.Type: ...

class SetTy(lief.dwarf.Type):
    @property
    def underlying_type(self) -> lief.dwarf.Type: ...

class Shared(lief.dwarf.Type):
    @property
    def underlying_type(self) -> lief.dwarf.Type: ...

class StringTy(lief.dwarf.Type):
    pass

class Structure(ClassLike):
    pass

class Subroutine(lief.dwarf.Type):
    @property
    def parameters(self) -> list[Optional[lief.dwarf.Parameter]]: ...

class TemplateAlias(lief.dwarf.Type):
    @property
    def parameters(self) -> list[Optional[lief.dwarf.Parameter]]: ...

    @property
    def underlying_type(self) -> lief.dwarf.Type: ...

class Thrown(lief.dwarf.Type):
    @property
    def underlying_type(self) -> lief.dwarf.Type: ...

class Typedef(lief.dwarf.Type):
    @property
    def underlying_type(self) -> lief.dwarf.Type: ...

class Union(ClassLike):
    pass

class Volatile(lief.dwarf.Type):
    @property
    def underlying_type(self) -> lief.dwarf.Type: ...
