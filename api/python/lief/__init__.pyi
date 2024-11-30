from collections.abc import Sequence
import enum
import io
import lief
import os
from typing import Iterator, Optional, Union, overload

from . import (
    ART as ART,
    Android as Android,
    DEX as DEX,
    ELF as ELF,
    MachO as MachO,
    OAT as OAT,
    PE as PE,
    VDEX as VDEX,
    assembly as assembly,
    dsc as dsc,
    dwarf as dwarf,
    logging as logging,
    objc as objc,
    pdb as pdb
)


class Binary(Object):
    class VA_TYPES(enum.Enum):
        AUTO = 0

        VA = 2

        RVA = 1

    class FORMATS(enum.Enum):
        UNKNOWN = 0

        ELF = 1

        PE = 2

        MACHO = 3

        OAT = 4

    class it_sections:
        def __getitem__(self, arg: int, /) -> Section: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_sections: ...

        def __next__(self) -> Section: ...

    class it_symbols:
        def __getitem__(self, arg: int, /) -> Symbol: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_symbols: ...

        def __next__(self) -> Symbol: ...

    class it_relocations:
        def __getitem__(self, arg: int, /) -> Relocation: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_relocations: ...

        def __next__(self) -> Relocation: ...

    @property
    def debug_info(self) -> DebugInfo: ...

    @property
    def format(self) -> Binary.FORMATS: ...

    @property
    def is_pie(self) -> bool: ...

    @property
    def has_nx(self) -> bool: ...

    @property
    def header(self) -> Header: ...

    @property
    def entrypoint(self) -> int: ...

    def remove_section(self, name: str, clear: bool = False) -> None: ...

    @property
    def sections(self) -> Binary.it_sections: ...

    @property
    def relocations(self) -> Binary.it_relocations: ...

    @property
    def exported_functions(self) -> list[Function]: ...

    @property
    def imported_functions(self) -> list[Function]: ...

    @property
    def libraries(self) -> list[Union[str,bytes]]: ...

    @property
    def symbols(self) -> Binary.it_symbols: ...

    def has_symbol(self, symbol_name: str) -> bool: ...

    def get_symbol(self, symbol_name: str) -> Symbol: ...

    def get_function_address(self, function_name: str) -> Union[int, lief_errors]: ...

    @overload
    def patch_address(self, address: int, patch_value: Sequence[int], va_type: Binary.VA_TYPES = Binary.VA_TYPES.AUTO) -> None: ...

    @overload
    def patch_address(self, address: int, patch_value: int, size: int = 8, va_type: Binary.VA_TYPES = Binary.VA_TYPES.AUTO) -> None: ...

    def get_content_from_virtual_address(self, virtual_address: int, size: int, va_type: Binary.VA_TYPES = Binary.VA_TYPES.AUTO) -> memoryview: ...

    def get_int_from_virtual_address(self, address: int, interger_size: int, type: Binary.VA_TYPES = Binary.VA_TYPES.AUTO) -> Optional[int]: ...

    @property
    def abstract(self) -> lief.Binary: ...

    @property
    def concrete(self) -> lief.ELF.Binary | lief.PE.Binary | lief.MachO.Binary: ...

    @property
    def ctor_functions(self) -> list[Function]: ...

    def xref(self, virtual_address: int) -> list[int]: ...

    def offset_to_virtual_address(self, offset: int, slide: int = 0) -> Union[int, lief_errors]: ...

    @property
    def imagebase(self) -> int: ...

    @property
    def original_size(self) -> int: ...

    @overload
    def disassemble(self, address: int) -> Iterator[Optional[assembly.Instruction]]: ...

    @overload
    def disassemble(self, address: int, size: int) -> Iterator[Optional[assembly.Instruction]]: ...

    @overload
    def disassemble(self, function_name: str) -> Iterator[Optional[assembly.Instruction]]: ...

    def disassemble_from_bytes(self, buffer: bytes, address: int = 0) -> Iterator[Optional[assembly.Instruction]]: ...

    def assemble(self, address: int, assembly: str) -> bytes: ...

    def __str__(self) -> str: ...

class DebugInfo:
    class FORMAT(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> DebugInfo.FORMAT: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        DWARF = 1

        PDB = 2

    @property
    def format(self) -> DebugInfo.FORMAT: ...

class Function(Symbol):
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, arg: str, /) -> None: ...

    @overload
    def __init__(self, arg: int, /) -> None: ...

    @overload
    def __init__(self, arg0: str, arg1: int, /) -> None: ...

    class FLAGS(enum.Flag):
        @staticmethod
        def from_value(arg: int, /) -> Function.FLAGS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        NONE = 0

        IMPORTED = 16

        EXPORTED = 8

        CONSTRUCTOR = 1

        DESTRUCTOR = 2

        DEBUG_INFO = 4

    def add(self, flag: Function.FLAGS) -> Function: ...

    def has(self, flag: Function.FLAGS) -> bool: ...

    @property
    def flags(self) -> Function.FLAGS: ...

    @property
    def flags_list(self) -> list[Function.FLAGS]: ...

    address: int

    def __str__(self) -> str: ...

class Header(Object):
    class ARCHITECTURES(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Header.ARCHITECTURES: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        ARM = 1

        ARM64 = 2

        MIPS = 3

        X86 = 4

        X86_64 = 5

        PPC = 6

        SPARC = 7

        SYSZ = 8

        XCORE = 9

        RISCV = 10

        LOONGARCH = 11

    class ENDIANNESS(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Header.ENDIANNESS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        BIG = 1

        LITTLE = 2

    class MODES(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Header.MODES: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        NONE = 0

        BITS_16 = 1

        BITS_32 = 2

        BITS_64 = 4

        THUMB = 8

        ARM64E = 16

    class OBJECT_TYPES(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Header.OBJECT_TYPES: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        EXECUTABLE = 1

        LIBRARY = 2

        OBJECT = 3

    @property
    def architecture(self) -> Header.ARCHITECTURES: ...

    @property
    def modes(self) -> Header.MODES: ...

    @property
    def modes_list(self) -> list[Header.MODES]: ...

    @property
    def entrypoint(self) -> int: ...

    @property
    def object_type(self) -> Header.OBJECT_TYPES: ...

    @property
    def endianness(self) -> Header.ENDIANNESS: ...

    @property
    def is_32(self) -> bool: ...

    @property
    def is_64(self) -> bool: ...

    def __str__(self) -> str: ...

class Object:
    def __hash__(self) -> int: ...

    def __eq__(self, arg, /) -> bool: ...

class PLATFORMS(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> PLATFORMS: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    UNKNOWN = 3

    LINUX = 1

    ANDROID = 2

    WINDOWS = 3

    IOS = 4

    OSX = 5

class Relocation(Object):
    address: int

    size: int

    def __str__(self) -> str: ...

class Section(Object):
    name: Union[str, bytes]

    @property
    def fullname(self) -> bytes: ...

    size: int

    offset: int

    virtual_address: int

    content: memoryview

    @property
    def entropy(self) -> float: ...

    @overload
    def search(self, number: int, pos: int = 0, size: int = 0) -> Optional[int]: ...

    @overload
    def search(self, str: str, pos: int = 0) -> Optional[int]: ...

    @overload
    def search(self, bytes: bytes, pos: int = 0) -> Optional[int]: ...

    @overload
    def search_all(self, number: int, size: int = 0) -> list[int]: ...

    @overload
    def search_all(self, str: str) -> list[int]: ...

    def __str__(self) -> str: ...

class Symbol(Object):
    name: Union[str, bytes]

    value: int

    size: int

    def __str__(self) -> str: ...

__commit__: str = ...

__extended__: bool = ...

__is_tagged__: bool = ...

__tag__: str = ...

def current_platform() -> PLATFORMS: ...

class debug_location_t:
    line: int

    file: str

    def __repr__(self) -> str: ...

def demangle(mangled: str) -> Optional[str]: ...

def disable_leak_warning() -> None: ...

@overload
def hash(arg: Object, /) -> int: ... # type: ignore

@overload
def hash(arg: Sequence[int], /) -> int: ... # type: ignore

@overload
def hash(arg: bytes, /) -> int: ... # type: ignore

@overload
def hash(arg: str, /) -> int: ... # type: ignore

@overload
def is_art(path: str) -> bool: ...

@overload
def is_art(raw: Sequence[int]) -> bool: ...

@overload
def is_dex(path: str) -> bool: ...

@overload
def is_dex(raw: Sequence[int]) -> bool: ...

@overload
def is_elf(filename: str) -> bool: ...

@overload
def is_elf(raw: Sequence[int]) -> bool: ...

@overload
def is_macho(filename: str) -> bool: ...

@overload
def is_macho(raw: Sequence[int]) -> bool: ...

@overload
def is_oat(binary: ELF.Binary) -> bool: ...

@overload
def is_oat(path: str) -> bool: ...

@overload
def is_oat(raw: Sequence[int]) -> bool: ...

@overload
def is_pe(file: str) -> bool: ...

@overload
def is_pe(raw: Sequence[int]) -> bool: ...

@overload
def is_vdex(path: str) -> bool: ...

@overload
def is_vdex(raw: Sequence[int]) -> bool: ...

class lief_errors(enum.Enum):
    read_error = 1

    not_found = 2

    not_implemented = 3

    not_supported = 4

    corrupted = 5

    conversion_error = 6

    read_out_of_bound = 7

    asn1_bad_tag = 8

    file_error = 9

    file_format_error = 10

    parsing_error = 11

    build_error = 12

    data_too_large = 13

    require_extended_version = 14

class ok_error_t:
    @property
    def is_error(self) -> bool: ...

    @property
    def is_value(self) -> bool: ...

    @property
    def error(self) -> lief_errors: ...

    @property
    def value(self) -> ok_t: ...

    def __bool__(self) -> bool: ...

class ok_t:
    def __bool__(self) -> bool: ...

@overload
def parse(raw: bytes) -> Optional[Binary]: ...

@overload
def parse(filepath: str) -> Optional[Binary]: ...

@overload
def parse(obj: Union[io.IOBase | os.PathLike]) -> Optional[Binary]: ...

class range_t:
    low: int

    high: int

    @property
    def size(self) -> int: ...

    def __repr__(self) -> str: ...

    def __str__(self) -> str: ...

def to_json(arg: Object, /) -> str: ...
