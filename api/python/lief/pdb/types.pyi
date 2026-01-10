import enum
from typing import Iterator, Optional, Union as _Union

import lief.pdb


class Simple(lief.pdb.Type):
    class TYPES(enum.Enum):
        UNKNOWN = 0

        VOID = 3

        SCHAR = 16

        UCHAR = 32

        RCHAR = 112

        WCHAR = 113

        CHAR16 = 122

        CHAR32 = 123

        CHAR8 = 124

        SBYTE = 104

        UBYTE = 105

        SSHORT = 17

        USHORT = 33

        SINT16 = 114

        UINT16 = 115

        SLONG = 18

        ULONG = 34

        SINT32 = 116

        UINT32 = 117

        SQUAD = 19

        UQUAD = 35

        SINT64 = 118

        UINT64 = 119

        SOCTA = 20

        UOCTA = 36

        SINT128 = 120

        UINT128 = 121

        FLOAT16 = 70

        FLOAT32 = 64

        FLOAT32_PARTIAL_PRECISION = 69

        FLOAT48 = 68

        FLOAT64 = 65

        FLOAT80 = 66

        FLOAT128 = 67

        COMPLEX16 = 86

        COMPLEX32 = 80

        COMPLEX32_PARTIAL_PRECISION = 85

        COMPLEX48 = 84

        COMPLEX64 = 81

        COMPLEX80 = 82

        COMPLEX128 = 83

        BOOL8 = 48

        BOOL16 = 49

        BOOL32 = 50

        BOOL64 = 51

        BOOL128 = 52

    class MODES(enum.Enum):
        DIRECT = 0

        FAR_POINTER = 512

        HUGE_POINTER = 768

        NEAR_POINTER32 = 1024

        FAR_POINTER32 = 1280

        NEAR_POINTER64 = 1536

        NEAR_POINTER128 = 1792

    @property
    def type(self) -> Simple.TYPES: ...

    @property
    def modes(self) -> Simple.MODES: ...

    @property
    def is_pointer(self) -> bool: ...

    @property
    def is_signed(self) -> bool: ...

class Array(lief.pdb.Type):
    @property
    def numberof_elements(self) -> int: ...

    @property
    def element_type(self) -> Optional[lief.pdb.Type]: ...

    @property
    def index_type(self) -> Optional[lief.pdb.Type]: ...

class BitField(lief.pdb.Type):
    pass

class ClassLike(lief.pdb.Type):
    @property
    def attributes(self) -> Iterator[Optional[Attribute]]: ...

    @property
    def methods(self) -> Iterator[Optional[Method]]: ...

    @property
    def unique_name(self) -> str: ...

class Class(ClassLike):
    pass

class Structure(ClassLike):
    pass

class Interface(ClassLike):
    pass

class Attribute:
    @property
    def name(self) -> str: ...

    @property
    def type(self) -> Optional[lief.pdb.Type]: ...

    @property
    def field_offset(self) -> int: ...

class Method:
    @property
    def name(self) -> str: ...

class Enum(lief.pdb.Type):
    class Entry:
        @property
        def name(self) -> str: ...

        @property
        def value(self) -> int: ...

    @property
    def unique_name(self) -> str: ...

    @property
    def entries(self) -> list[Enum.Entry]: ...

    @property
    def underlying_type(self) -> lief.pdb.Type: ...

    def find_entry(self, value: int) -> Enum.Entry | None: ...

class Function(lief.pdb.Type):
    @property
    def return_type(self) -> Optional[lief.pdb.Type]: ...

    @property
    def parameters(self) -> list[Optional[lief.pdb.Type]]: ...

class Modifier(lief.pdb.Type):
    @property
    def underlying_type(self) -> Optional[lief.pdb.Type]: ...

class Pointer(lief.pdb.Type):
    @property
    def underlying_type(self) -> Optional[lief.pdb.Type]: ...

class Union(ClassLike):
    pass
