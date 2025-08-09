import enum
import io
import os
from typing import Iterator, Optional, Union, overload

import lief
import lief.PE
import lief.assembly


class Header:
    class KIND(enum.Enum):
        UNKNOWN = 0

        REGULAR = 1

        BIGOBJ = 2

    @property
    def kind(self) -> Header.KIND: ...

    machine: lief.PE.Header.MACHINE_TYPES

    nb_sections: int

    pointerto_symbol_table: int

    nb_symbols: int

    timedatestamp: int

    def __str__(self) -> str: ...

    def copy(self) -> Optional[Header]: ...

class RegularHeader(Header):
    sizeof_optionalheader: int

    characteristics: int

class BigObjHeader(Header):
    version: int

    @property
    def uuid(self) -> memoryview: ...

    sizeof_data: int

    flags: int

    metadata_size: int

    metadata_offset: int

class Binary:
    class it_section:
        def __getitem__(self, arg: int, /) -> Section: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_section: ...

        def __next__(self) -> Section: ...

    class it_relocations:
        def __getitem__(self, arg: int, /) -> Relocation: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_relocations: ...

        def __next__(self) -> Relocation: ...

    class it_symbols:
        def __getitem__(self, arg: int, /) -> Symbol: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_symbols: ...

        def __next__(self) -> Symbol: ...

    class it_strings_table:
        def __getitem__(self, arg: int, /) -> String: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_strings_table: ...

        def __next__(self) -> String: ...

    class it_functions:
        def __getitem__(self, arg: int, /) -> Symbol: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_functions: ...

        def __next__(self) -> Symbol: ...

    @property
    def header(self) -> Header: ...

    @property
    def sections(self) -> Binary.it_section: ...

    @property
    def relocations(self) -> Binary.it_relocations: ...

    @property
    def symbols(self) -> lief.PE.Binary.it_symbols: ...

    @property
    def functions(self) -> Binary.it_functions: ...

    @property
    def string_table(self) -> lief.PE.Binary.it_strings_table: ...

    def find_string(self, offset: int) -> String: ...

    def find_function(self, name: str) -> Symbol: ...

    def find_demangled_function(self, name: str) -> Symbol: ...

    @overload
    def disassemble(self, function: Symbol) -> Iterator[Optional[lief.assembly.Instruction]]: ...

    @overload
    def disassemble(self, function_name: str) -> Iterator[Optional[lief.assembly.Instruction]]: ...

    def disassemble_from_bytes(self, buffer: bytes, address: int = 0) -> Iterator[Optional[lief.assembly.Instruction]]: ...

    def __str__(self) -> str: ...

class ParserConfig:
    def __init__(self) -> None: ...

    default_conf: ParserConfig = ...

    all: ParserConfig = ...

def parse(obj: Union[str | io.IOBase | os.PathLike | bytes | list[int]], config: ParserConfig = ...) -> Optional[Binary]: ...

class String:
    string: str

    offset: int

    def __str__(self) -> str: ...

class Symbol(lief.Symbol):
    class it_auxiliary_symbols_t:
        def __getitem__(self, arg: int, /) -> AuxiliarySymbol: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Symbol.it_auxiliary_symbols_t: ...

        def __next__(self) -> AuxiliarySymbol: ...

    class STORAGE_CLASS(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Symbol.STORAGE_CLASS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        END_OF_FUNCTION = -1

        NONE = 0

        AUTOMATIC = 1

        EXTERNAL = 2

        STATIC = 3

        REGISTER = 4

        EXTERNAL_DEF = 5

        LABEL = 6

        UNDEFINED_LABEL = 7

        MEMBER_OF_STRUCT = 8

        ARGUMENT = 9

        STRUCT_TAG = 10

        MEMBER_OF_UNION = 11

        UNION_TAG = 12

        TYPE_DEFINITION = 13

        UNDEFINED_STATIC = 14

        ENUM_TAG = 15

        MEMBER_OF_ENUM = 16

        REGISTER_PARAM = 17

        BIT_FIELD = 18

        BLOCK = 100

        FUNCTION = 101

        END_OF_STRUCT = 102

        FILE = 103

        SECTION = 104

        WEAK_EXTERNAL = 105

        CLR_TOKEN = 107

    class BASE_TYPE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Symbol.BASE_TYPE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        NULL = 0

        VOID = 1

        CHAR = 2

        SHORT = 3

        INT = 4

        LONG = 5

        FLOAT = 6

        DOUBLE = 7

        STRUCT = 8

        UNION = 9

        ENUM = 10

        MOE = 11

        BYTE = 12

        WORD = 13

        UINT = 14

        DWORD = 15

    class COMPLEX_TYPE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Symbol.COMPLEX_TYPE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        NULL = 0

        POINTER = 1

        FUNCTION = 2

        ARRAY = 3

    type: int

    @property
    def base_type(self) -> Symbol.BASE_TYPE: ...

    @property
    def complex_type(self) -> Symbol.COMPLEX_TYPE: ...

    @property
    def storage_class(self) -> Symbol.STORAGE_CLASS: ...

    section_idx: int

    @property
    def section(self) -> Section: ...

    @property
    def is_external(self) -> bool: ...

    @property
    def is_absolute(self) -> bool: ...

    @property
    def is_weak_external(self) -> bool: ...

    @property
    def is_undefined(self) -> bool: ...

    @property
    def is_function_line_info(self) -> bool: ...

    @property
    def is_file_record(self) -> bool: ...

    @property
    def is_function(self) -> bool: ...

    @property
    def auxiliary_symbols(self) -> Symbol.it_auxiliary_symbols_t: ...

    @property
    def coff_name(self) -> String: ...

    @property
    def demangled_name(self) -> str: ...

    def __str__(self) -> str: ...

class Section(lief.Section):
    class it_relocations:
        def __getitem__(self, arg: int, /) -> Relocation: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Section.it_relocations: ...

        def __next__(self) -> Relocation: ...

    class it_symbols:
        def __getitem__(self, arg: int, /) -> Symbol: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Section.it_symbols: ...

        def __next__(self) -> Symbol: ...

    class ComdatInfo:
        @property
        def symbol(self) -> Symbol: ...

        @property
        def kind(self) -> AuxiliarySectionDefinition.COMDAT_SELECTION: ...

    virtual_size: int

    sizeof_raw_data: int

    pointerto_raw_data: int

    pointerto_relocation: int

    pointerto_line_numbers: int

    numberof_relocations: int

    numberof_line_numbers: int

    characteristics: int

    @property
    def characteristics_lists(self) -> list[lief.PE.Section.CHARACTERISTICS]: ...

    def has_characteristic(self, characteristic: lief.PE.Section.CHARACTERISTICS) -> bool: ...

    @property
    def is_discardable(self) -> bool: ...

    @property
    def relocations(self) -> Section.it_relocations: ...

    @property
    def symbols(self) -> Section.it_symbols: ...

    @property
    def has_extended_relocations(self) -> bool: ...

    @property
    def comdat_info(self) -> Section.ComdatInfo | None: ...

    def __str__(self) -> str: ...

class Relocation(lief.Relocation):
    class TYPE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Relocation.TYPE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 4294967295

        AMD64_ABSOLUTE = 262144

        AMD64_ADDR32 = 262146

        AMD64_ADDR32NB = 262147

        AMD64_ADDR64 = 262145

        AMD64_PAIR = 262159

        AMD64_REL32 = 262148

        AMD64_REL32_1 = 262149

        AMD64_REL32_2 = 262150

        AMD64_REL32_3 = 262151

        AMD64_REL32_4 = 262152

        AMD64_REL32_5 = 262153

        AMD64_SECREL = 262155

        AMD64_SECREL7 = 262156

        AMD64_SECTION = 262154

        AMD64_SREL32 = 262158

        AMD64_SSPAN32 = 262160

        AMD64_TOKEN = 262157

        ARM64_ABSOLUTE = 1048576

        ARM64_ADDR32 = 1048577

        ARM64_ADDR32NB = 1048578

        ARM64_ADDR64 = 1048590

        ARM64_BRANCH14 = 1048592

        ARM64_BRANCH19 = 1048591

        ARM64_BRANCH26 = 1048579

        ARM64_PAGEBASE_REL21 = 1048580

        ARM64_PAGEOFFSET_12A = 1048582

        ARM64_PAGEOFFSET_12L = 1048583

        ARM64_REL21 = 1048581

        ARM64_REL32 = 1048593

        ARM64_SECREL = 1048584

        ARM64_SECREL_HIGH12A = 1048586

        ARM64_SECREL_LOW12A = 1048585

        ARM64_SECREL_LOW12L = 1048587

        ARM64_SECTION = 1048589

        ARM64_TOKEN = 1048588

        ARM_ABSOLUTE = 524288

        ARM_ADDR32 = 524289

        ARM_ADDR32NB = 524290

        ARM_BLX11 = 524297

        ARM_BLX23T = 524309

        ARM_BLX24 = 524296

        ARM_BRANCH11 = 524292

        ARM_BRANCH20T = 524306

        ARM_BRANCH24 = 524291

        ARM_BRANCH24T = 524308

        ARM_MOV32A = 524304

        ARM_MOV32T = 524305

        ARM_PAIR = 524310

        ARM_REL32 = 524298

        ARM_SECREL = 524303

        ARM_SECTION = 524302

        ARM_TOKEN = 524293

        I386_ABSOLUTE = 131072

        I386_DIR16 = 131073

        I386_DIR32 = 131078

        I386_DIR32NB = 131079

        I386_REL16 = 131074

        I386_REL32 = 131092

        I386_SECREL = 131083

        I386_SECREL7 = 131085

        I386_SECTION = 131082

        I386_SEG12 = 131081

        I386_TOKEN = 131084

        MIPS_ABSOLUTE = 2097152

        MIPS_GPREL = 2097158

        MIPS_JMPADDR = 2097155

        MIPS_JMPADDR16 = 2097168

        MIPS_LITERAL = 2097159

        MIPS_PAIR = 2097189

        MIPS_REFHALF = 2097153

        MIPS_REFHI = 2097156

        MIPS_REFLO = 2097157

        MIPS_REFWORD = 2097154

        MIPS_REFWORDNB = 2097186

        MIPS_SECREL = 2097163

        MIPS_SECRELHI = 2097165

        MIPS_SECRELLO = 2097164

        MIPS_SECTION = 2097162

    @property
    def symbol_idx(self) -> int: ...

    @property
    def symbol(self) -> Symbol: ...

    @property
    def type(self) -> Relocation.TYPE: ...

    @property
    def section(self) -> Section: ...

    def __str__(self) -> str: ...

class AuxiliarySymbol:
    class TYPE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> AuxiliarySymbol.TYPE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        CLR_TOKEN = 1

        FUNC_DEF = 2

        BF_AND_EF = 3

        WEAK_EXTERNAL = 4

        FILE = 5

        SEC_DEF = 6

    @property
    def type(self) -> AuxiliarySymbol.TYPE: ...

    @property
    def payload(self) -> memoryview: ...

    def __str__(self) -> str: ...

    def copy(self) -> Optional[AuxiliarySymbol]: ...

class AuxiliaryCLRToken(AuxiliarySymbol):
    @property
    def aux_type(self) -> int: ...

    @property
    def reserved(self) -> int: ...

    @property
    def symbol_idx(self) -> int: ...

    @property
    def symbol(self) -> Symbol: ...

    @property
    def rgb_reserved(self) -> memoryview: ...

class AuxiliaryFunctionDefinition(AuxiliarySymbol):
    @property
    def tag_index(self) -> int: ...

    @property
    def total_size(self) -> int: ...

    @property
    def ptr_to_line_number(self) -> int: ...

    @property
    def ptr_to_next_func(self) -> int: ...

    @property
    def padding(self) -> int: ...

class AuxiliaryWeakExternal(AuxiliarySymbol):
    class CHARACTERISTICS(enum.Enum):
        SEARCH_NOLIBRARY = 1

        SEARCH_LIBRARY = 2

        SEARCH_ALIAS = 3

        ANTI_DEPENDENCY = 4

    @property
    def sym_idx(self) -> int: ...

    @property
    def characteristics(self) -> AuxiliaryWeakExternal.CHARACTERISTICS: ...

    @property
    def padding(self) -> memoryview: ...

class AuxiliarybfAndefSymbol(AuxiliarySymbol):
    pass

class AuxiliarySectionDefinition(AuxiliarySymbol):
    class COMDAT_SELECTION(enum.Enum):
        NONE = 0

        NODUPLICATES = 1

        ANY = 2

        SAME_SIZE = 3

        EXACT_MATCH = 4

        ASSOCIATIVE = 5

        LARGEST = 6

    @property
    def length(self) -> int: ...

    @property
    def nb_relocs(self) -> int: ...

    @property
    def nb_line_numbers(self) -> int: ...

    @property
    def checksum(self) -> int: ...

    @property
    def section_idx(self) -> int: ...

    @property
    def selection(self) -> AuxiliarySectionDefinition.COMDAT_SELECTION: ...

    @property
    def reserved(self) -> int: ...

class AuxiliaryFile(AuxiliarySymbol):
    @property
    def filename(self) -> str: ...
