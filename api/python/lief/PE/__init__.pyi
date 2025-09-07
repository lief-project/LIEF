from collections.abc import Callable, Sequence
import enum
import io
import lief.PE
import os
from typing import Iterator, Optional, Union, overload

from . import (
    unwind_aarch64 as unwind_aarch64,
    unwind_x64 as unwind_x64
)
import lief
import lief.COFF


class PE_TYPE(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> PE_TYPE: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    PE32 = 267

    PE32_PLUS = 523

class ALGORITHMS(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> ALGORITHMS: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    UNKNOWN = 0

    SHA_512 = 1

    SHA_384 = 2

    SHA_256 = 3

    SHA_1 = 4

    MD5 = 5

    MD4 = 6

    MD2 = 7

    RSA = 8

    EC = 9

    MD5_RSA = 10

    SHA1_DSA = 11

    SHA1_RSA = 12

    SHA_256_RSA = 13

    SHA_384_RSA = 14

    SHA_512_RSA = 15

    SHA1_ECDSA = 16

    SHA_256_ECDSA = 17

    SHA_384_ECDSA = 18

    SHA_512_ECDSA = 19

class ParserConfig:
    def __init__(self) -> None: ...

    parse_signature: bool

    parse_exports: bool

    parse_imports: bool

    parse_rsrc: bool

    parse_reloc: bool

    parse_exceptions: bool

    parse_arm64x_binary: bool

    default_conf: ParserConfig = ...

    all: ParserConfig = ...

    def __str__(self) -> str: ...

def parse(obj: Union[str | io.IOBase | os.PathLike | bytes | list[int]], config: ParserConfig = ...) -> Optional[Binary]: ...

class DosHeader(lief.Object):
    @staticmethod
    def create(arg: PE_TYPE, /) -> DosHeader: ...

    magic: int

    used_bytes_in_last_page: int

    file_size_in_pages: int

    numberof_relocation: int

    header_size_in_paragraphs: int

    minimum_extra_paragraphs: int

    maximum_extra_paragraphs: int

    initial_relative_ss: int

    initial_sp: int

    checksum: int

    initial_ip: int

    initial_relative_cs: int

    addressof_relocation_table: int

    overlay_number: int

    oem_id: int

    oem_info: int

    addressof_new_exeheader: int

    def copy(self) -> DosHeader: ...

    def __str__(self) -> str: ...

class Header(lief.Object):
    class MACHINE_TYPES(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Header.MACHINE_TYPES: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        ALPHA = 388

        ALPHA64 = 644

        AM33 = 467

        AMD64 = 34404

        ARM = 448

        ARMNT = 452

        ARM64 = 43620

        EBC = 3772

        I386 = 332

        IA64 = 512

        LOONGARCH32 = 25138

        LOONGARCH64 = 25188

        M32R = 36929

        MIPS16 = 614

        MIPSFPU = 870

        MIPSFPU16 = 1126

        POWERPC = 496

        POWERPCFP = 497

        POWERPCBE = 498

        R4000 = 358

        SH3 = 418

        SH3DSP = 419

        SH4 = 422

        SH5 = 424

        THUMB = 450

        WCEMIPSV2 = 361

        ARM64EC = 42561

        ARM64X = 42574

        CHPE_X86 = 14948

    class CHARACTERISTICS(enum.Flag):
        @staticmethod
        def from_value(arg: int, /) -> Header.CHARACTERISTICS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        RELOCS_STRIPPED = 1

        EXECUTABLE_IMAGE = 2

        LINE_NUMS_STRIPPED = 4

        LOCAL_SYMS_STRIPPED = 8

        AGGRESSIVE_WS_TRIM = 16

        LARGE_ADDRESS_AWARE = 32

        BYTES_REVERSED_LO = 128

        NEED_32BIT_MACHINE = 256

        DEBUG_STRIPPED = 512

        REMOVABLE_RUN_FROM_SWAP = 1024

        NET_RUN_FROM_SWAP = 2048

        SYSTEM = 4096

        DLL = 8192

        UP_SYSTEM_ONLY = 16384

        BYTES_REVERSED_HI = 32768

    @staticmethod
    def create(type: PE_TYPE) -> Header: ...

    signature: list[int]

    machine: Header.MACHINE_TYPES

    numberof_sections: int

    time_date_stamps: int

    pointerto_symbol_table: int

    numberof_symbols: int

    sizeof_optional_header: int

    characteristics: int

    def has_characteristic(self, characteristic: Header.CHARACTERISTICS) -> bool: ...

    def add_characteristic(self, characteristic: Header.CHARACTERISTICS) -> None: ...

    def remove_characteristic(self, characteristic: Header.CHARACTERISTICS) -> None: ...

    @property
    def characteristics_list(self) -> list[Header.CHARACTERISTICS]: ...

    def copy(self) -> Header: ...

    def __str__(self) -> str: ...

class OptionalHeader(lief.Object):
    class SUBSYSTEM(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> OptionalHeader.SUBSYSTEM: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        NATIVE = 1

        WINDOWS_GUI = 2

        WINDOWS_CUI = 3

        OS2_CUI = 5

        POSIX_CUI = 7

        NATIVE_WINDOWS = 8

        WINDOWS_CE_GUI = 9

        EFI_APPLICATION = 10

        EFI_BOOT_SERVICE_DRIVER = 11

        EFI_RUNTIME_DRIVER = 12

        EFI_ROM = 13

        XBOX = 14

        WINDOWS_BOOT_APPLICATION = 16

    class DLL_CHARACTERISTICS(enum.IntFlag):
        def __repr__(self, /): ...

        @staticmethod
        def from_value(arg: int, /) -> OptionalHeader.DLL_CHARACTERISTICS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        HIGH_ENTROPY_VA = 32

        DYNAMIC_BASE = 64

        FORCE_INTEGRITY = 128

        NX_COMPAT = 256

        NO_ISOLATION = 512

        NO_SEH = 1024

        NO_BIND = 2048

        APPCONTAINER = 4096

        WDM_DRIVER = 8192

        GUARD_CF = 16384

        TERMINAL_SERVER_AWARE = 32768

    @staticmethod
    def create(type: PE_TYPE) -> OptionalHeader: ...

    magic: PE_TYPE

    major_linker_version: int

    minor_linker_version: int

    sizeof_code: int

    sizeof_initialized_data: int

    sizeof_uninitialized_data: int

    addressof_entrypoint: int

    baseof_code: int

    baseof_data: int

    imagebase: int

    section_alignment: int

    file_alignment: int

    major_operating_system_version: int

    minor_operating_system_version: int

    major_image_version: int

    minor_image_version: int

    major_subsystem_version: int

    minor_subsystem_version: int

    win32_version_value: int

    sizeof_image: int

    sizeof_headers: int

    checksum: int

    subsystem: OptionalHeader.SUBSYSTEM

    dll_characteristics: int

    def add(self, characteristic: OptionalHeader.DLL_CHARACTERISTICS) -> None: ...

    def remove(self, characteristic: OptionalHeader.DLL_CHARACTERISTICS) -> None: ...

    @property
    def dll_characteristics_lists(self) -> list[OptionalHeader.DLL_CHARACTERISTICS]: ...

    def has(self, characteristics: OptionalHeader.DLL_CHARACTERISTICS) -> bool: ...

    sizeof_stack_reserve: int

    sizeof_stack_commit: int

    sizeof_heap_reserve: int

    sizeof_heap_commit: int

    loader_flags: int

    numberof_rva_and_size: int

    def __iadd__(self, arg: OptionalHeader.DLL_CHARACTERISTICS, /) -> OptionalHeader: ...

    def __isub__(self, arg: OptionalHeader.DLL_CHARACTERISTICS, /) -> OptionalHeader: ...

    def __contains__(self, arg: OptionalHeader.DLL_CHARACTERISTICS, /) -> bool: ...

    def copy(self) -> OptionalHeader: ...

    def __str__(self) -> str: ...

class RichHeader(lief.Object):
    def __init__(self) -> None: ...

    class it_entries:
        def __getitem__(self, arg: int, /) -> RichEntry: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> RichHeader.it_entries: ...

        def __next__(self) -> RichEntry: ...

    key: int

    @property
    def entries(self) -> RichHeader.it_entries: ...

    @overload
    def add_entry(self, entry: RichEntry) -> None: ...

    @overload
    def add_entry(self, id: int, build_id: int, count: int) -> None: ...

    @overload
    def raw(self) -> list[int]: ...

    @overload
    def raw(self, xor_key: int) -> list[int]: ...

    @overload
    def hash(self, algo: ALGORITHMS) -> list[int]: ...

    @overload
    def hash(self, algo: ALGORITHMS, xor_key: int) -> list[int]: ...

    def copy(self) -> RichHeader: ...

    def __str__(self) -> str: ...

class RichEntry(lief.Object):
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, id: int, build_id: int, count: int) -> None: ...

    id: int

    build_id: int

    count: int

    def copy(self) -> RichEntry: ...

    def __str__(self) -> str: ...

class DataDirectory(lief.Object):
    def __init__(self) -> None: ...

    class TYPES(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> DataDirectory.TYPES: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        EXPORT_TABLE = 0

        IMPORT_TABLE = 1

        RESOURCE_TABLE = 2

        EXCEPTION_TABLE = 3

        CERTIFICATE_TABLE = 4

        BASE_RELOCATION_TABLE = 5

        DEBUG_DIR = 6

        ARCHITECTURE = 7

        GLOBAL_PTR = 8

        TLS_TABLE = 9

        LOAD_CONFIG_TABLE = 10

        BOUND_IMPORT = 11

        IAT = 12

        DELAY_IMPORT_DESCRIPTOR = 13

        CLR_RUNTIME_HEADER = 14

        RESERVED = 15

        UNKNOWN = 16

    rva: int

    size: int

    @property
    def section(self) -> Section: ...

    @property
    def content(self) -> memoryview: ...

    @property
    def type(self) -> DataDirectory.TYPES: ...

    @property
    def has_section(self) -> bool: ...

    def copy(self) -> DataDirectory: ...

    def __str__(self) -> str: ...

class Section(lief.Section):
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, name: str, content: Sequence[int]) -> None: ...

    @overload
    def __init__(self, name: str) -> None: ...

    class CHARACTERISTICS(enum.Flag):
        @staticmethod
        def from_value(arg: int, /) -> Section.CHARACTERISTICS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        TYPE_NO_PAD = 8

        CNT_CODE = 32

        CNT_INITIALIZED_DATA = 64

        CNT_UNINITIALIZED_DATA = 128

        LNK_OTHER = 256

        LNK_INFO = 512

        LNK_REMOVE = 2048

        LNK_COMDAT = 4096

        GPREL = 32768

        MEM_PURGEABLE = 65536

        MEM_16BIT = 131072

        MEM_LOCKED = 262144

        MEM_PRELOAD = 524288

        ALIGN_1BYTES = 1048576

        ALIGN_2BYTES = 2097152

        ALIGN_4BYTES = 3145728

        ALIGN_8BYTES = 4194304

        ALIGN_16BYTES = 5242880

        ALIGN_32BYTES = 6291456

        ALIGN_64BYTES = 7340032

        ALIGN_128BYTES = 8388608

        ALIGN_256BYTES = 9437184

        ALIGN_512BYTES = 10485760

        ALIGN_1024BYTES = 11534336

        ALIGN_2048BYTES = 12582912

        ALIGN_4096BYTES = 13631488

        ALIGN_8192BYTES = 14680064

        LNK_NRELOC_OVFL = 16777216

        MEM_DISCARDABLE = 33554432

        MEM_NOT_CACHED = 67108864

        MEM_NOT_PAGED = 134217728

        MEM_SHARED = 268435456

        MEM_EXECUTE = 536870912

        MEM_READ = 1073741824

        MEM_WRITE = 2147483648

    virtual_size: int

    sizeof_raw_data: int

    pointerto_raw_data: int

    pointerto_relocation: int

    pointerto_line_numbers: int

    numberof_relocations: int

    numberof_line_numbers: int

    characteristics: int

    @property
    def characteristics_lists(self) -> list[Section.CHARACTERISTICS]: ...

    def has_characteristic(self, characteristic: Section.CHARACTERISTICS) -> bool: ...

    @property
    def is_discardable(self) -> bool: ...

    @property
    def coff_string(self) -> lief.COFF.String: ...

    @property
    def padding(self) -> bytes: ...

    def copy(self) -> Section: ...

    def __str__(self) -> str: ...

class Relocation(lief.Object):
    def __init__(self) -> None: ...

    class it_entries:
        def __getitem__(self, arg: int, /) -> RelocationEntry: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Relocation.it_entries: ...

        def __next__(self) -> RelocationEntry: ...

    virtual_address: int

    block_size: int

    @property
    def entries(self) -> Relocation.it_entries: ...

    def add_entry(self, new_entry: RelocationEntry) -> RelocationEntry: ...

    def copy(self) -> Relocation: ...

    def __str__(self) -> str: ...

class RelocationEntry(lief.Relocation):
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, arg0: int, arg1: RelocationEntry.BASE_TYPES, /) -> None: ...

    class BASE_TYPES(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> RelocationEntry.BASE_TYPES: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = -1

        ABS = 0

        HIGH = 1

        LOW = 2

        HIGHLOW = 3

        HIGHADJ = 4

        MIPS_JMPADDR = 261

        ARM_MOV32 = 517

        RISCV_HI20 = 1029

        SECTION = 6

        THUMB_MOV32 = 2055

        RISCV_LOW12I = 4103

        RISCV_LOW12S = 8200

        MIPS_JMPADDR16 = 9

        DIR64 = 10

        HIGH3ADJ = 11

    @property
    def data(self) -> int: ...

    position: int

    type: RelocationEntry.BASE_TYPES

    def __str__(self) -> str: ...

class Export(lief.Object):
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, name: str, entries: Sequence[ExportEntry]) -> None: ...

    class it_entries:
        def __getitem__(self, arg: int, /) -> ExportEntry: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Export.it_entries: ...

        def __next__(self) -> ExportEntry: ...

    name: Union[str, bytes]

    export_flags: int

    timestamp: int

    major_version: int

    minor_version: int

    ordinal_base: int

    @property
    def entries(self) -> Export.it_entries: ...

    @property
    def name_rva(self) -> int: ...

    @property
    def export_addr_table_rva(self) -> int: ...

    @property
    def export_addr_table_cnt(self) -> int: ...

    @property
    def names_addr_table_rva(self) -> int: ...

    @property
    def names_addr_table_cnt(self) -> int: ...

    @property
    def ord_addr_table_rva(self) -> int: ...

    @overload
    def find_entry(self, name: str) -> ExportEntry: ...

    @overload
    def find_entry(self, ordinal: int) -> ExportEntry: ...

    def find_entry_at(self, rva_addr: int) -> ExportEntry: ...

    @overload
    def add_entry(self, exp: ExportEntry) -> ExportEntry: ...

    @overload
    def add_entry(self, name: str, addr: int) -> ExportEntry: ...

    @overload
    def remove_entry(self, entry: ExportEntry) -> bool: ...

    @overload
    def remove_entry(self, name: str) -> bool: ...

    @overload
    def remove_entry(self, rva: int) -> bool: ...

    def copy(self) -> Export: ...

    def __str__(self) -> str: ...

class ExportEntry(lief.Symbol):
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, name: str, addr: int) -> None: ...

    class forward_information_t:
        library: str

        function: str

        def __str__(self) -> str: ...

    name: Union[str, bytes]

    ordinal: int

    address: int

    is_extern: bool

    @property
    def is_forwarded(self) -> bool: ...

    @property
    def forward_information(self) -> ExportEntry.forward_information_t: ...

    @property
    def function_rva(self) -> int: ...

    @property
    def demangled_name(self) -> str: ...

    def set_forward_info(self, lib: str, function: str) -> None: ...

    def __str__(self) -> str: ...

class TLS(lief.Object):
    def __init__(self) -> None: ...

    callbacks: list[int]

    addressof_index: int

    addressof_callbacks: int

    sizeof_zero_fill: int

    characteristics: int

    addressof_raw_data: tuple[int, int]

    data_template: memoryview

    @property
    def has_section(self) -> bool: ...

    @property
    def has_data_directory(self) -> bool: ...

    @property
    def directory(self) -> DataDirectory: ...

    @property
    def section(self) -> Section: ...

    def add_callback(self, addr: int) -> TLS: ...

    def copy(self) -> TLS: ...

    def __str__(self) -> str: ...

class Import(lief.Object):
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, library_name: str) -> None: ...

    class it_entries:
        def __getitem__(self, arg: int, /) -> ImportEntry: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Import.it_entries: ...

        def __next__(self) -> ImportEntry: ...

    @property
    def forwarder_chain(self) -> int: ...

    @property
    def timedatestamp(self) -> int: ...

    @property
    def entries(self) -> Import.it_entries: ...

    name: Union[str, bytes]

    @property
    def directory(self) -> DataDirectory: ...

    @property
    def iat_directory(self) -> DataDirectory: ...

    import_address_table_rva: int

    import_lookup_table_rva: int

    def get_function_rva_from_iat(self, function_name: str) -> Union[int, lief.lief_errors]: ...

    @overload
    def add_entry(self, entry: ImportEntry) -> ImportEntry: ...

    @overload
    def add_entry(self, function_name: str) -> ImportEntry: ...

    def get_entry(self, function_name: str) -> ImportEntry: ...

    @property
    def name_rva(self) -> int: ...

    @overload
    def remove_entry(self, name: str) -> bool: ...

    @overload
    def remove_entry(self, ord: int) -> bool: ...

    def __str__(self) -> str: ...

class ImportEntry(lief.Symbol):
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, import_name: str) -> None: ...

    @overload
    def __init__(self, data: int, type: PE_TYPE) -> None: ...

    name: Union[str, bytes]

    data: int

    @property
    def demangled_name(self) -> str: ...

    @property
    def is_ordinal(self) -> bool: ...

    @property
    def ordinal(self) -> int: ...

    @property
    def hint(self) -> int: ...

    @property
    def iat_value(self) -> int: ...

    @property
    def ilt_value(self) -> int: ...

    @property
    def iat_address(self) -> int: ...

    def copy(self) -> ImportEntry: ...

    def __str__(self) -> str: ...

class DelayImport(lief.Object):
    def __init__(self, library_name: str) -> None: ...

    class it_entries:
        def __getitem__(self, arg: int, /) -> DelayImportEntry: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> DelayImport.it_entries: ...

        def __next__(self) -> DelayImportEntry: ...

    @property
    def entries(self) -> DelayImport.it_entries: ...

    name: Union[str, bytes]

    attribute: int

    handle: int

    iat: int

    names_table: int

    biat: int

    uiat: int

    timestamp: int

    def copy(self) -> DelayImport: ...

    def __str__(self) -> str: ...

class DelayImportEntry(lief.Symbol):
    def __init__(self) -> None: ...

    @property
    def demangled_name(self) -> str: ...

    name: Union[str, bytes]

    data: int

    @property
    def is_ordinal(self) -> bool: ...

    @property
    def ordinal(self) -> int: ...

    @property
    def hint(self) -> int: ...

    @property
    def iat_value(self) -> int: ...

    def copy(self) -> DelayImportEntry: ...

    def __str__(self) -> str: ...

class ExceptionInfo:
    class ARCH(enum.Enum):
        UNKNOWN = 0

        ARM64 = 1

        X86_64 = 2

    @property
    def arch(self) -> ExceptionInfo.ARCH: ...

    @property
    def rva_start(self) -> int: ...

    @property
    def offset(self) -> int: ...

    def copy(self) -> Optional[ExceptionInfo]: ...

    def __str__(self) -> str: ...

class RuntimeFunctionX64(ExceptionInfo):
    class UNWIND_FLAGS(enum.Flag):
        @staticmethod
        def from_value(arg: int, /) -> RuntimeFunctionX64.UNWIND_FLAGS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        EXCEPTION_HANDLER = 1

        TERMINATE_HANDLER = 2

        CHAIN_INFO = 4

    class UNWIND_OPCODES(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> RuntimeFunctionX64.UNWIND_OPCODES: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        PUSH_NONVOL = 0

        ALLOC_LARGE = 1

        ALLOC_SMALL = 2

        SET_FPREG = 3

        SAVE_NONVOL = 4

        SAVE_NONVOL_FAR = 5

        SAVE_XMM128 = 8

        SAVE_XMM128_FAR = 9

        PUSH_MACHFRAME = 10

        EPILOG = 6

        SPARE = 7

    class UNWIND_REG(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> RuntimeFunctionX64.UNWIND_REG: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        RAX = 0

        RCX = 1

        RDX = 2

        RBX = 3

        RSP = 4

        RBP = 5

        RSI = 6

        RDI = 7

        R8 = 8

        R9 = 9

        R10 = 10

        R11 = 11

        R12 = 12

        R13 = 13

        R14 = 14

        R15 = 15

    class unwind_info_t:
        version: int

        flags: int

        sizeof_prologue: int

        count_opcodes: int

        frame_reg: int

        frame_reg_offset: int

        raw_opcodes: list[int]

        handler: int | None

        chained: RuntimeFunctionX64

        def has(self, arg: RuntimeFunctionX64.UNWIND_FLAGS, /) -> bool: ...

        @property
        def opcodes(self) -> list[Optional[unwind_x64.Code]]: ...

        def __str__(self) -> str: ...

    @property
    def rva_end(self) -> int: ...

    @property
    def unwind_rva(self) -> int: ...

    @property
    def size(self) -> int: ...

    @property
    def unwind_info(self) -> RuntimeFunctionX64.unwind_info_t: ...

class RuntimeFunctionAArch64(ExceptionInfo):
    class PACKED_FLAGS(enum.Enum):
        UNPACKED = 0

        PACKED = 1

        PACKED_FRAGMENT = 2

        RESERVED = 3

    @property
    def length(self) -> int: ...

    @property
    def flag(self) -> RuntimeFunctionAArch64.PACKED_FLAGS: ...

    @property
    def rva_end(self) -> int: ...

class Debug(lief.Object):
    def __init__(self) -> None: ...

    class TYPES(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Debug.TYPES: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        COFF = 1

        CODEVIEW = 2

        FPO = 3

        MISC = 4

        EXCEPTION = 5

        FIXUP = 6

        OMAP_TO_SRC = 7

        OMAP_FROM_SRC = 8

        BORLAND = 9

        RESERVED10 = 10

        CLSID = 11

        VC_FEATURE = 12

        POGO = 13

        ILTCG = 14

        MPX = 15

        REPRO = 16

        PDBCHECKSUM = 19

        EX_DLLCHARACTERISTICS = 20

    characteristics: int

    timestamp: int

    major_version: int

    minor_version: int

    @property
    def type(self) -> Debug.TYPES: ...

    sizeof_data: int

    addressof_rawdata: int

    pointerto_rawdata: int

    @property
    def section(self) -> Section: ...

    @property
    def payload(self) -> memoryview: ...

    def copy(self) -> Optional[Debug]: ...

    def __str__(self) -> str: ...

class CodeView(Debug):
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, arg: CodeView.SIGNATURES, /) -> None: ...

    class SIGNATURES(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> CodeView.SIGNATURES: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        PDB_70 = 1396986706

        PDB_20 = 808534606

        CV_50 = 825311822

        CV_41 = 959464014

    @property
    def cv_signature(self) -> CodeView.SIGNATURES: ...

    def __str__(self) -> str: ...

class CodeViewPDB(CodeView):
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, filename: str) -> None: ...

    @property
    def parent(self) -> lief.PE.CodeView: ...

    @property
    def guid(self) -> str: ...

    signature: list[int]

    age: int

    filename: Union[str, bytes]

    def __str__(self) -> str: ...

class Repro(Debug):
    hash: memoryview

    def __str__(self) -> str: ...

class Pogo(Debug):
    def __init__(self) -> None: ...

    class it_entries:
        def __getitem__(self, arg: int, /) -> PogoEntry: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Pogo.it_entries: ...

        def __next__(self) -> PogoEntry: ...

    class SIGNATURES(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Pogo.SIGNATURES: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 268435455

        ZERO = 0

        LCTG = 1280590663

        PGI = 1346849024

    @property
    def entries(self) -> Pogo.it_entries: ...

    @property
    def signature(self) -> Pogo.SIGNATURES: ...

    def __str__(self) -> str: ...

class PogoEntry(lief.Object):
    def __init__(self) -> None: ...

    name: Union[str, bytes]

    start_rva: int

    size: int

    def copy(self) -> PogoEntry: ...

    def __str__(self) -> str: ...

class PDBChecksum(Debug):
    def __init__(self, algo: PDBChecksum.HASH_ALGO, hash: Sequence[int]) -> None: ...

    class HASH_ALGO(enum.Enum):
        UNKNOWN = 0

        SHA256 = 1

    hash: memoryview

    algorithm: PDBChecksum.HASH_ALGO

    def __str__(self) -> str: ...

class VCFeature(Debug):
    pre_vcpp: int

    c_cpp: int

    gs: int

    sdl: int

    guards: int

class ExDllCharacteristics(Debug):
    class CHARACTERISTICS(enum.Flag):
        @staticmethod
        def from_value(arg: int, /) -> ExDllCharacteristics.CHARACTERISTICS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        CET_COMPAT = 1

        CET_COMPAT_STRICT_MODE = 2

        CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE = 4

        CET_DYNAMIC_APIS_ALLOW_IN_PROC = 8

        CET_RESERVED_1 = 16

        CET_RESERVED_2 = 32

        FORWARD_CFI_COMPAT = 64

        HOTPATCH_COMPATIBLE = 128

    def has(self, characteristic: ExDllCharacteristics.CHARACTERISTICS) -> bool: ...

    @property
    def ex_characteristics(self) -> ExDllCharacteristics.CHARACTERISTICS: ...

    @property
    def ex_characteristics_list(self) -> list[ExDllCharacteristics.CHARACTERISTICS]: ...

class FPO(Debug):
    class FRAME_TYPE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> FPO.FRAME_TYPE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        FPO = 0

        TRAP = 1

        TSS = 2

        NON_FPO = 3

    class entry_t:
        rva: int

        proc_size: int

        nb_locals: int

        parameters_size: int

        prolog_size: int

        nb_saved_regs: int

        use_seh: bool

        use_bp: bool

        reserved: int

        type: FPO.FRAME_TYPE

        def __str__(self) -> str: ...

    class it_entries:
        def __getitem__(self, arg: int, /) -> FPO.entry_t: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> FPO.it_entries: ...

        def __next__(self) -> FPO.entry_t: ...

    @property
    def entries(self) -> FPO.it_entries: ...

class ResourcesManager(lief.Object):
    def __init__(self, node: ResourceNode) -> None: ...

    class it_const_dialogs:
        def __getitem__(self, arg: int, /) -> ResourceDialog: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> ResourcesManager.it_const_dialogs: ...

        def __next__(self) -> ResourceDialog: ...

    class it_const_icons:
        def __getitem__(self, arg: int, /) -> ResourceIcon: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> ResourcesManager.it_const_icons: ...

        def __next__(self) -> ResourceIcon: ...

    class it_const_accelerators:
        def __getitem__(self, arg: int, /) -> ResourceAccelerator: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> ResourcesManager.it_const_accelerators: ...

        def __next__(self) -> ResourceAccelerator: ...

    class string_entry_t:
        string: str

        id: int

        def __str__(self) -> str: ...

    class TYPE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> ResourcesManager.TYPE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        CURSOR = 1

        BITMAP = 2

        ICON = 3

        MENU = 4

        DIALOG = 5

        STRING = 6

        FONTDIR = 7

        FONT = 8

        ACCELERATOR = 9

        RCDATA = 10

        MESSAGETABLE = 11

        GROUP_CURSOR = 12

        GROUP_ICON = 14

        VERSION = 16

        DLGINCLUDE = 17

        PLUGPLAY = 19

        VXD = 20

        ANICURSOR = 21

        ANIICON = 22

        HTML = 23

        MANIFEST = 24

    @property
    def has_manifest(self) -> bool: ...

    manifest: Union[str, bytes]

    @property
    def has_version(self) -> bool: ...

    @property
    def version(self) -> list[ResourceVersion]: ...

    @property
    def has_icons(self) -> bool: ...

    @property
    def icons(self) -> ResourcesManager.it_const_icons: ...

    def change_icon(self, old_one: ResourceIcon, new_one: ResourceIcon) -> None: ...

    @property
    def has_dialogs(self) -> bool: ...

    @property
    def dialogs(self) -> ResourcesManager.it_const_dialogs: ...

    @property
    def types(self) -> list[ResourcesManager.TYPE]: ...

    def add_icon(self, icon: ResourceIcon) -> None: ...

    def has_type(self, type: ResourcesManager.TYPE) -> bool: ...

    @property
    def has_string_table(self) -> bool: ...

    @property
    def string_table(self) -> list[ResourcesManager.string_entry_t]: ...

    @property
    def has_html(self) -> bool: ...

    @property
    def html(self) -> list[str]: ...

    @property
    def has_accelerator(self) -> bool: ...

    @property
    def accelerator(self) -> ResourcesManager.it_const_accelerators: ...

    def get_node_type(self, type: ResourcesManager.TYPE) -> ResourceNode: ...

    def print(self, max_depth: int = 0) -> str: ...

    def __str__(self) -> str: ...

class ResourceNode(lief.Object):
    class it_childs:
        def __getitem__(self, arg: int, /) -> ResourceNode: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> ResourceNode.it_childs: ...

        def __next__(self) -> ResourceNode: ...

    @staticmethod
    def parse(bytes: bytes, rva: int) -> Optional[ResourceNode]: ...

    id: int

    @property
    def is_directory(self) -> bool: ...

    @property
    def is_data(self) -> bool: ...

    @property
    def has_name(self) -> bool: ...

    name: str

    @property
    def childs(self) -> ResourceNode.it_childs: ...

    def add_child(self, node: ResourceNode) -> ResourceNode: ...

    @overload
    def delete_child(self, node: ResourceNode) -> None: ...

    @overload
    def delete_child(self, id: int) -> None: ...

    @property
    def depth(self) -> int: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def copy(self) -> Optional[ResourceNode]: ...

    def __str__(self) -> str: ...

class ResourceData(ResourceNode):
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, content: Sequence[int], code_page: int = 0) -> None: ...

    code_page: int

    content: memoryview

    reserved: int

    @property
    def offset(self) -> int: ...

    def __str__(self) -> str: ...

class ResourceDirectory(ResourceNode):
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, arg: int, /) -> None: ...

    characteristics: int

    time_date_stamp: int

    major_version: int

    minor_version: int

    numberof_name_entries: int

    numberof_id_entries: int

    def __str__(self) -> str: ...

class ResourceVersion(lief.Object):
    class fixed_file_info_t:
        class VERSION_OS(enum.Enum):
            DOS_WINDOWS16 = 65537

            DOS_WINDOWS32 = 65540

            NT = 262144

            NT_WINDOWS32 = 262148

            OS216 = 131072

            OS216_PM16 = 131074

            OS232 = 196608

            OS232_PM32 = 196611

            PM16 = 2

            PM32 = 3

            UNKNOWN = 0

            WINCE = 327680

            WINDOWS16 = 1

            WINDOWS32 = 4

        class FILE_TYPE(enum.Enum):
            UNKNOWN = 0

            APP = 1

            DLL = 2

            DRV = 3

            FONT = 4

            STATIC_LIB = 7

            VXD = 5

        class FILE_FLAGS(enum.Enum):
            DEBUG = 1

            INFO_INFERRED = 16

            PATCHED = 4

            PRERELEASE = 2

            PRIVATEBUILD = 8

            SPECIALBUILD = 32

        class FILE_TYPE_DETAILS(enum.Enum):
            DRV_COMM = 8589934602

            DRV_DISPLAY = 8589934596

            DRV_INPUTMETHOD = 8589934603

            DRV_INSTALLABLE = 8589934600

            DRV_KEYBOARD = 8589934594

            DRV_LANGUAGE = 8589934595

            DRV_MOUSE = 8589934597

            DRV_NETWORK = 8589934598

            DRV_PRINTER = 8589934593

            DRV_SOUND = 8589934601

            DRV_SYSTEM = 8589934599

            DRV_VERSIONED_PRINTER = 12

            FONT_RASTER = 17179869185

            FONT_TRUETYPE = 17179869187

            FONT_VECTOR = 17179869186

            UNKNOWN = 0

        signature: int

        struct_version: int

        file_version_ms: int

        file_version_ls: int

        product_version_ms: int

        product_version_ls: int

        file_flags_mask: int

        file_flags: int

        file_os: int

        file_type: int

        file_subtype: int

        file_date_ms: int

        file_date_ls: int

        def has(self, flag: ResourceVersion.fixed_file_info_t.FILE_FLAGS) -> bool: ...

        @property
        def flags(self) -> list[ResourceVersion.fixed_file_info_t.FILE_FLAGS]: ...

        @property
        def file_type_details(self) -> ResourceVersion.fixed_file_info_t.FILE_TYPE_DETAILS: ...

        def __str__(self) -> str: ...

    @property
    def key(self) -> str: ...

    @property
    def type(self) -> int: ...

    @property
    def file_info(self) -> ResourceVersion.fixed_file_info_t: ...

    @property
    def string_file_info(self) -> ResourceStringFileInfo: ...

    @property
    def var_file_info(self) -> ResourceVarFileInfo: ...

    def __str__(self) -> str: ...

class ResourceStringTable(lief.Object):
    class it_entries:
        def __getitem__(self, arg: int, /) -> ResourceStringTable.entry_t: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> ResourceStringTable.it_entries: ...

        def __next__(self) -> ResourceStringTable.entry_t: ...

    class entry_t:
        key: str

        value: str

        def __bool__(self) -> bool: ...

    @property
    def key(self) -> str: ...

    @property
    def type(self) -> int: ...

    @property
    def entries(self) -> ResourceStringTable.it_entries: ...

    def get(self, key: str) -> str | None: ...

    def __getitem__(self, arg: str, /) -> str | None: ...

class ResourceStringFileInfo(lief.Object):
    class it_elements:
        def __getitem__(self, arg: int, /) -> ResourceStringTable: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> ResourceStringFileInfo.it_elements: ...

        def __next__(self) -> ResourceStringTable: ...

    @property
    def type(self) -> int: ...

    @property
    def key(self) -> str: ...

    @property
    def children(self) -> ResourceStringFileInfo.it_elements: ...

    def __str__(self) -> str: ...

class ResourceVar:
    @property
    def type(self) -> int: ...

    @property
    def key(self) -> str: ...

    @property
    def values(self) -> list[int]: ...

    def __str__(self) -> str: ...

class ResourceVarFileInfo(lief.Object):
    class it_vars:
        def __getitem__(self, arg: int, /) -> ResourceVar: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> ResourceVarFileInfo.it_vars: ...

        def __next__(self) -> ResourceVar: ...

    @property
    def type(self) -> int: ...

    @property
    def key(self) -> str: ...

    @property
    def vars(self) -> ResourceVarFileInfo.it_vars: ...

    def __str__(self) -> str: ...

class ResourceIcon(lief.Object):
    id: int

    lang: int

    sublang: int

    width: int

    height: int

    color_count: int

    reserved: int

    planes: int

    bit_count: int

    pixels: memoryview

    def save(self, filepath: str) -> None: ...

    def serialize(self) -> bytes: ...

    @staticmethod
    def from_serialization(arg: bytes, /) -> Union[ResourceIcon, lief.lief_errors]: ...

    def __str__(self) -> str: ...

class ResourceDialog(lief.Object):
    class DIALOG_STYLES(enum.Flag):
        @staticmethod
        def from_value(arg: int, /) -> ResourceDialog.DIALOG_STYLES: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        ABSALIGN = 1

        SYSMODAL = 2

        LOCALEDIT = 32

        SETFONT = 64

        MODALFRAME = 128

        NOIDLEMSG = 256

        SETFOREGROUND = 512

        S3DLOOK = 4

        FIXEDSYS = 8

        NOFAILCREATE = 16

        CONTROL = 1024

        CENTER = 2048

        CENTERMOUSE = 4096

        CONTEXTHELP = 8192

        SHELLFONT = 72

    class WINDOW_STYLES(enum.Flag):
        @staticmethod
        def from_value(arg: int, /) -> ResourceDialog.WINDOW_STYLES: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        OVERLAPPED = 0

        POPUP = 2147483648

        CHILD = 1073741824

        MINIMIZE = 536870912

        VISIBLE = 268435456

        DISABLED = 134217728

        CLIPSIBLINGS = 67108864

        CLIPCHILDREN = 33554432

        MAXIMIZE = 16777216

        CAPTION = 12582912

        BORDER = 8388608

        DLGFRAME = 4194304

        VSCROLL = 2097152

        HSCROLL = 1048576

        SYSMENU = 524288

        THICKFRAME = 262144

        GROUP = 131072

        TABSTOP = 65536

    class WINDOW_EXTENDED_STYLES(enum.Flag):
        @staticmethod
        def from_value(arg: int, /) -> ResourceDialog.WINDOW_EXTENDED_STYLES: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        DLGMODALFRAME = 1

        NOPARENTNOTIFY = 4

        TOPMOST = 8

        ACCEPTFILES = 16

        TRANSPARENT_STY = 32

        MDICHILD = 64

        TOOLWINDOW = 128

        WINDOWEDGE = 256

        CLIENTEDGE = 512

        CONTEXTHELP = 1024

        RIGHT = 4096

        LEFT = 0

        RTLREADING = 8192

        LEFTSCROLLBAR = 16384

        CONTROLPARENT = 65536

        STATICEDGE = 131072

        APPWINDOW = 262144

    class CONTROL_STYLES(enum.Flag):
        @staticmethod
        def from_value(arg: int, /) -> ResourceDialog.CONTROL_STYLES: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        TOP = 1

        NOMOVEY = 2

        BOTTOM = 3

        NORESIZE = 4

        NOPARENTALIGN = 8

        ADJUSTABLE = 32

        NODIVIDER = 64

        VERT = 128

        LEFT = 129

        RIGHT = 131

        NOMOVEX = 130

    class TYPE(enum.Enum):
        UNKNOWN = 0

        REGULAR = 1

        EXTENDED = 2

    class Item:
        style: int

        extended_style: int

        id: int

        x: int

        y: int

        cx: int

        cy: int

        @overload
        def has(self, style: ResourceDialog.WINDOW_STYLES) -> bool: ...

        @overload
        def has(self, style: ResourceDialog.CONTROL_STYLES) -> bool: ...

        @property
        def window_styles(self) -> list[ResourceDialog.WINDOW_STYLES]: ...

        @property
        def control_styles(self) -> list[ResourceDialog.CONTROL_STYLES]: ...

        @property
        def clazz(self) -> Optional[Union[int, str]]: ...

        @property
        def title(self) -> Optional[Union[int, str]]: ...

        @property
        def creation_data(self) -> memoryview: ...

        def __str__(self) -> str: ...

    @property
    def type(self) -> ResourceDialog.TYPE: ...

    style: int

    extended_style: int

    x: int

    y: int

    cx: int

    cy: int

    @overload
    def has(self, arg: ResourceDialog.DIALOG_STYLES, /) -> bool: ...

    @overload
    def has(self, arg: ResourceDialog.WINDOW_STYLES, /) -> bool: ...

    @overload
    def has(self, arg: ResourceDialog.WINDOW_EXTENDED_STYLES, /) -> bool: ...

    @property
    def styles_list(self) -> list[ResourceDialog.DIALOG_STYLES]: ...

    @property
    def windows_styles_list(self) -> list[ResourceDialog.WINDOW_STYLES]: ...

    @property
    def windows_ext_styles_list(self) -> list[ResourceDialog.WINDOW_EXTENDED_STYLES]: ...

    title: str

    @property
    def menu(self) -> Optional[Union[int, str]]: ...

    @property
    def window_class(self) -> Optional[Union[int, str]]: ...

    def copy(self) -> Optional[ResourceDialog]: ...

    def __str__(self) -> str: ...

class ResourceDialogExtended(ResourceDialog):
    def __init__(self) -> None: ...

    class it_items:
        def __getitem__(self, arg: int, /) -> ResourceDialogExtended.Item: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> ResourceDialogExtended.it_items: ...

        def __next__(self) -> ResourceDialogExtended.Item: ...

    class font_t:
        point_size: int

        weight: int

        italic: bool

        charset: int

        typeface: str

        def __bool__(self) -> bool: ...

        def __str__(self) -> str: ...

    class Item(ResourceDialog.Item):
        def __init__(self) -> None: ...

        help_id: int

        def __str__(self) -> str: ...

    @property
    def version(self) -> int: ...

    @property
    def signature(self) -> int: ...

    @property
    def help_id(self) -> int: ...

    @property
    def items(self) -> ResourceDialogExtended.it_items: ...

    @property
    def font(self) -> ResourceDialogExtended.font_t: ...

    def add_item(self, item: ResourceDialogExtended.Item) -> None: ...

    def __str__(self) -> str: ...

class ResourceDialogRegular(ResourceDialog):
    def __init__(self) -> None: ...

    class it_items:
        def __getitem__(self, arg: int, /) -> ResourceDialogRegular.Item: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> ResourceDialogRegular.it_items: ...

        def __next__(self) -> ResourceDialogRegular.Item: ...

    class font_t:
        point_size: int

        name: str

        def __bool__(self) -> bool: ...

        def __str__(self) -> str: ...

    class Item(ResourceDialog.Item):
        def __init__(self) -> None: ...

        def __str__(self) -> str: ...

    @property
    def nb_items(self) -> int: ...

    @property
    def items(self) -> ResourceDialogRegular.it_items: ...

    @property
    def font(self) -> ResourceDialogRegular.font_t: ...

    def add_item(self, item: ResourceDialogRegular.Item) -> None: ...

    def __str__(self) -> str: ...

class ACCELERATOR_CODES(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> ACCELERATOR_CODES: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    LBUTTON = 1

    RBUTTON = 2

    CANCEL = 3

    MBUTTON = 4

    XBUTTON1_K = 5

    XBUTTON2_K = 6

    BACK = 8

    TAB = 9

    CLEAR = 12

    RETURN = 13

    SHIFT = 16

    CONTROL = 17

    MENU = 18

    PAUSE = 19

    CAPITAL = 20

    KANA = 21

    IME_ON = 22

    JUNJA = 23

    FINAL = 24

    KANJI = 25

    IME_OFF = 26

    ESCAPE = 27

    CONVERT = 28

    NONCONVERT = 29

    ACCEPT = 30

    MODECHANGE = 31

    SPACE = 32

    PRIOR = 33

    NEXT = 34

    END = 35

    HOME = 36

    LEFT = 37

    UP = 38

    RIGHT = 39

    DOWN = 40

    SELECT = 41

    PRINT = 42

    EXECUTE = 43

    SNAPSHOT = 44

    INSERT = 45

    DELETE_K = 46

    HELP = 47

    NUM_0 = 48

    NUM_1 = 49

    NUM_2 = 50

    NUM_3 = 51

    NUM_4 = 52

    NUM_5 = 53

    NUM_6 = 54

    NUM_7 = 55

    NUM_8 = 56

    NUM_9 = 57

    A = 65

    B = 66

    C = 67

    D = 68

    E = 69

    F = 70

    G = 71

    H = 72

    I = 73

    J = 74

    K = 75

    L = 76

    M = 77

    N = 78

    O = 79

    P = 80

    Q = 81

    R = 82

    S = 83

    T = 84

    U = 85

    V = 86

    W = 87

    X = 88

    Y = 89

    Z = 90

    LWIN = 91

    RWIN = 92

    APPS = 93

    SLEEP = 95

    NUMPAD0 = 96

    NUMPAD1 = 97

    NUMPAD2 = 98

    NUMPAD3 = 99

    NUMPAD4 = 100

    NUMPAD5 = 101

    NUMPAD6 = 102

    NUMPAD7 = 103

    NUMPAD8 = 104

    NUMPAD9 = 105

    MULTIPLY = 106

    ADD = 107

    SEPARATOR = 108

    SUBTRACT = 109

    DECIMAL = 110

    DIVIDE = 111

    F1 = 112

    F2 = 113

    F3 = 114

    F4 = 115

    F5 = 116

    F6 = 117

    F7 = 118

    F8 = 119

    F9 = 120

    F10 = 121

    F11 = 122

    F12 = 123

    F13 = 124

    F14 = 125

    F15 = 126

    F16 = 127

    F17 = 128

    F18 = 129

    F19 = 130

    F20 = 131

    F21 = 132

    F22 = 133

    F23 = 134

    F24 = 135

    NUMLOCK = 144

    SCROLL = 145

    LSHIFT = 160

    RSHIFT = 161

    LCONTROL = 162

    RCONTROL = 163

    LMENU = 164

    RMENU = 165

    BROWSER_BACK = 166

    BROWSER_FORWARD = 167

    BROWSER_REFRESH = 168

    BROWSER_STOP = 169

    BROWSER_SEARCH = 170

    BROWSER_FAVORITES = 171

    BROWSER_HOME = 172

    VOLUME_MUTE = 173

    VOLUME_DOWN = 174

    VOLUME_UP = 175

    MEDIA_NEXT_TRACK = 176

    MEDIA_PREV_TRACK = 177

    MEDIA_STOP = 178

    MEDIA_PLAY_PAUSE = 179

    LAUNCH_MAIL = 180

    LAUNCH_MEDIA_SELECT = 181

    LAUNCH_APP1 = 182

    LAUNCH_APP2 = 183

    OEM_1 = 186

    OEM_PLUS = 187

    OEM_COMMA = 188

    OEM_MINUS = 189

    OEM_PERIOD = 190

    OEM_2 = 191

    OEM_4 = 219

    OEM_5 = 220

    OEM_6 = 221

    OEM_7 = 222

    OEM_8 = 223

    OEM_102 = 226

    PROCESSKEY = 229

    PACKET = 231

    ATTN = 246

    CRSEL = 247

    EXSEL = 248

    EREOF = 249

    PLAY = 250

    ZOOM = 251

    NONAME = 252

    PA1 = 253

    OEM_CLEAR = 254

class ResourceAccelerator(lief.Object):
    class FLAGS(enum.Flag):
        @staticmethod
        def from_value(arg: int, /) -> ResourceAccelerator.FLAGS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        VIRTKEY = 1

        NOINVERT = 2

        SHIFT = 4

        CONTROL = 8

        ALT = 16

        END = 128

    @property
    def flags(self) -> int: ...

    @property
    def ansi(self) -> int: ...

    @property
    def ansi_str(self) -> str: ...

    @property
    def id(self) -> int: ...

    @property
    def padding(self) -> int: ...

    def has(self, arg: ResourceAccelerator.FLAGS, /) -> bool: ...

    def add(self, arg: ResourceAccelerator.FLAGS, /) -> ResourceAccelerator: ...

    def remove(self, arg: ResourceAccelerator.FLAGS, /) -> ResourceAccelerator: ...

    def __str__(self) -> str: ...

class RESOURCE_LANGS(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> RESOURCE_LANGS: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    NEUTRAL = 0

    INVARIANT = 127

    AFRIKAANS = 54

    ALBANIAN = 28

    ARABIC = 1

    ARMENIAN = 43

    ASSAMESE = 77

    AZERI = 44

    BASQUE = 45

    BELARUSIAN = 35

    BANGLA = 69

    BULGARIAN = 2

    CATALAN = 3

    CHINESE = 4

    CROATIAN = 26

    BOSNIAN = 26

    CZECH = 5

    DANISH = 6

    DIVEHI = 101

    DUTCH = 19

    ENGLISH = 9

    ESTONIAN = 37

    FAEROESE = 56

    FARSI = 41

    FINNISH = 11

    FRENCH = 12

    GALICIAN = 86

    GEORGIAN = 55

    GERMAN = 7

    GREEK = 8

    GUJARATI = 71

    HEBREW = 13

    HINDI = 57

    HUNGARIAN = 14

    ICELANDIC = 15

    INDONESIAN = 33

    ITALIAN = 16

    JAPANESE = 17

    KANNADA = 75

    KASHMIRI = 96

    KAZAK = 63

    KONKANI = 87

    KOREAN = 18

    KYRGYZ = 64

    LATVIAN = 38

    LITHUANIAN = 39

    MACEDONIAN = 47

    MALAY = 62

    MALAYALAM = 76

    MANIPURI = 88

    MARATHI = 78

    MONGOLIAN = 80

    NEPALI = 97

    NORWEGIAN = 20

    ORIYA = 72

    POLISH = 21

    PORTUGUESE = 22

    PUNJABI = 70

    ROMANIAN = 24

    RUSSIAN = 25

    SANSKRIT = 79

    SERBIAN = 26

    SINDHI = 89

    SLOVAK = 27

    SLOVENIAN = 36

    SPANISH = 10

    SWAHILI = 65

    SWEDISH = 29

    SYRIAC = 90

    TAMIL = 73

    TATAR = 68

    TELUGU = 74

    THAI = 30

    TURKISH = 31

    UKRAINIAN = 34

    URDU = 32

    UZBEK = 67

    VIETNAMESE = 42

    GAELIC = 60

    MALTESE = 58

    MAORI = 40

    RHAETO_ROMANCE = 23

    SAMI = 59

    SORBIAN = 46

    SUTU = 48

    TSONGA = 49

    TSWANA = 50

    VENDA = 51

    XHOSA = 52

    ZULU = 53

    ESPERANTO = 143

    WALON = 144

    CORNISH = 145

    WELSH = 146

    BRETON = 147

    INUKTITUT = 93

    IRISH = 60

    LOWER_SORBIAN = 46

    PULAR = 103

    QUECHUA = 107

    TAMAZIGHT = 95

    TIGRINYA = 115

    VALENCIAN = 3

class Signature(lief.Object):
    class VERIFICATION_FLAGS(enum.Flag):
        @staticmethod
        def from_value(arg: int, /) -> Signature.VERIFICATION_FLAGS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        OK = 0

        INVALID_SIGNER = 1

        UNSUPPORTED_ALGORITHM = 2

        INCONSISTENT_DIGEST_ALGORITHM = 4

        CERT_NOT_FOUND = 8

        CORRUPTED_CONTENT_INFO = 16

        CORRUPTED_AUTH_DATA = 32

        MISSING_PKCS9_MESSAGE_DIGEST = 64

        BAD_DIGEST = 128

        BAD_SIGNATURE = 256

        NO_SIGNATURE = 512

        CERT_EXPIRED = 1024

        CERT_FUTURE = 2048

    class VERIFICATION_CHECKS(enum.Flag):
        @staticmethod
        def from_value(arg: int, /) -> Signature.VERIFICATION_CHECKS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        DEFAULT = 1

        HASH_ONLY = 2

        LIFETIME_SIGNING = 4

        SKIP_CERT_TIME = 8

    class it_const_crt:
        def __getitem__(self, arg: int, /) -> x509: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Signature.it_const_crt: ...

        def __next__(self) -> x509: ...

    class it_const_signers_t:
        def __getitem__(self, arg: int, /) -> SignerInfo: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Signature.it_const_signers_t: ...

        def __next__(self) -> SignerInfo: ...

    @overload
    @staticmethod
    def parse(path: Union[str | os.PathLike]) -> Optional[Signature]: ...

    @overload
    @staticmethod
    def parse(raw: Sequence[int], skip_header: bool = False) -> Optional[Signature]: ...

    @property
    def version(self) -> int: ...

    @property
    def digest_algorithm(self) -> ALGORITHMS: ...

    @property
    def content_info(self) -> ContentInfo: ...

    @property
    def certificates(self) -> Signature.it_const_crt: ...

    @property
    def signers(self) -> Signature.it_const_signers_t: ...

    def find_crt(self, serialno: Sequence[int]) -> x509: ...

    @overload
    def find_crt_subject(self, subject: str) -> x509: ...

    @overload
    def find_crt_subject(self, subject: str, serialno: Sequence[int]) -> x509: ...

    @overload
    def find_crt_issuer(self, issuer: str) -> x509: ...

    @overload
    def find_crt_issuer(self, issuer: str, serialno: Sequence[int]) -> x509: ...

    def check(self, checks: Signature.VERIFICATION_CHECKS = Signature.VERIFICATION_CHECKS.DEFAULT) -> Signature.VERIFICATION_FLAGS: ...

    @property
    def raw_der(self) -> memoryview: ...

    def __str__(self) -> str: ...

class RsaInfo:
    @property
    def has_public_key(self) -> bool: ...

    @property
    def has_private_key(self) -> bool: ...

    @property
    def N(self) -> bytes: ...

    @property
    def E(self) -> bytes: ...

    @property
    def D(self) -> bytes: ...

    @property
    def P(self) -> bytes: ...

    @property
    def Q(self) -> bytes: ...

    @property
    def key_size(self) -> int: ...

    @property
    def __len__(self) -> int: ...

    def __str__(self) -> str: ...

class x509(lief.Object):
    class VERIFICATION_FLAGS(enum.Flag):
        @staticmethod
        def from_value(arg: int, /) -> x509.VERIFICATION_FLAGS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        OK = 0

        BADCERT_EXPIRED = 1

        BADCERT_REVOKED = 2

        BADCERT_CN_MISMATCH = 4

        BADCERT_NOT_TRUSTED = 8

        BADCRL_NOT_TRUSTED = 16

        BADCRL_EXPIRED = 32

        BADCERT_MISSING = 64

        BADCERT_SKIP_VERIFY = 128

        BADCERT_OTHERNATURE = 256

        BADCERT_FUTURE = 512

        BADCRL_FUTURE = 1024

        BADCERT_KEY_USAGE = 2048

        BADCERT_EXT_KEY_USAGE = 4096

        BADCERT_NS_CERT_TYPE = 8192

        BADCERT_BAD_MD = 16384

        BADCERT_BAD_PK = 32768

        BADCERT_BAD_KEY = 65536

        BADCRL_BAD_MD = 131072

        BADCRL_BAD_PK = 262144

        BADCRL_BAD_KEY = 524288

    class KEY_TYPES(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> x509.KEY_TYPES: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        NONE = 0

        RSA = 1

        ECKEY = 2

        ECKEY_DH = 3

        ECDSA = 4

        RSA_ALT = 5

        RSASSA_PSS = 6

    class KEY_USAGE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> x509.KEY_USAGE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        DIGITAL_SIGNATURE = 0

        NON_REPUDIATION = 1

        KEY_ENCIPHERMENT = 2

        DATA_ENCIPHERMENT = 3

        KEY_AGREEMENT = 4

        KEY_CERT_SIGN = 5

        CRL_SIGN = 6

        ENCIPHER_ONLY = 7

        DECIPHER_ONLY = 8

    @overload
    @staticmethod
    def parse(path: str) -> list[x509]: ...

    @overload
    @staticmethod
    def parse(raw: Sequence[int]) -> list[x509]: ...

    @property
    def version(self) -> int: ...

    @property
    def serial_number(self) -> bytes: ...

    @property
    def signature_algorithm(self) -> str: ...

    @property
    def valid_from(self) -> list[int]: ...

    @property
    def valid_to(self) -> list[int]: ...

    @property
    def issuer(self) -> Union[str, bytes]: ...

    @property
    def subject(self) -> Union[str, bytes]: ...

    @property
    def raw(self) -> bytes: ...

    @property
    def key_type(self) -> x509.KEY_TYPES: ...

    @property
    def rsa_info(self) -> Optional[RsaInfo]: ...

    @property
    def key_usage(self) -> list[x509.KEY_USAGE]: ...

    @property
    def ext_key_usage(self) -> list[str]: ...

    @property
    def certificate_policies(self) -> list[str]: ...

    @property
    def is_ca(self) -> bool: ...

    @property
    def signature(self) -> bytes: ...

    def verify(self, ca: x509) -> x509.VERIFICATION_FLAGS: ...

    def is_trusted_by(self, ca_list: Sequence[x509]) -> x509.VERIFICATION_FLAGS: ...

    def __str__(self) -> str: ...

class ContentInfo(lief.Object):
    class Content(lief.Object):
        @property
        def content_type(self) -> str: ...

        def copy(self) -> Optional[ContentInfo.Content]: ...

    @property
    def content_type(self) -> str: ...

    @property
    def digest(self) -> bytes: ...

    @property
    def digest_algorithm(self) -> ALGORITHMS: ...

    @property
    def value(self) -> ContentInfo.Content: ...

    def copy(self) -> ContentInfo: ...

    def __str__(self) -> str: ...

class GenericContent(ContentInfo.Content):
    pass

class SpcIndirectData(ContentInfo.Content):
    @property
    def digest_algorithm(self) -> ALGORITHMS: ...

    @property
    def digest(self) -> memoryview: ...

    @property
    def file(self) -> str: ...

    @property
    def url(self) -> str: ...

    def __str__(self) -> str: ...

class SignerInfo(lief.Object):
    class it_const_attributes_t:
        def __getitem__(self, arg: int, /) -> Attribute: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> SignerInfo.it_const_attributes_t: ...

        def __next__(self) -> Attribute: ...

    @property
    def version(self) -> int: ...

    @property
    def serial_number(self) -> bytes: ...

    @property
    def issuer(self) -> Union[str, bytes]: ...

    @property
    def digest_algorithm(self) -> ALGORITHMS: ...

    @property
    def encryption_algorithm(self) -> ALGORITHMS: ...

    @property
    def encrypted_digest(self) -> bytes: ...

    @property
    def authenticated_attributes(self) -> SignerInfo.it_const_attributes_t: ...

    @property
    def unauthenticated_attributes(self) -> SignerInfo.it_const_attributes_t: ...

    def get_attribute(self, type: Attribute.TYPE) -> Attribute: ...

    def get_auth_attribute(self, type: Attribute.TYPE) -> Attribute: ...

    def get_unauth_attribute(self, type: Attribute.TYPE) -> Attribute: ...

    @property
    def cert(self) -> x509: ...

    def __str__(self) -> str: ...

class CodeIntegrity(lief.Object):
    def __init__(self) -> None: ...

    flags: int

    catalog: int

    catalog_offset: int

    reserved: int

    def __str__(self) -> str: ...

class Attribute(lief.Object):
    class TYPE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Attribute.TYPE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        CONTENT_TYPE = 1

        GENERIC_TYPE = 2

        SPC_SP_OPUS_INFO = 4

        MS_COUNTER_SIGN = 6

        MS_SPC_NESTED_SIGN = 7

        MS_SPC_STATEMENT_TYPE = 8

        SPC_RELAXED_PE_MARKER_CHECK = 5

        SIGNING_CERTIFICATE_V2 = 3

        MS_PLATFORM_MANIFEST_BINARY_ID = 9

        PKCS9_AT_SEQUENCE_NUMBER = 10

        PKCS9_COUNTER_SIGNATURE = 11

        PKCS9_MESSAGE_DIGEST = 12

        PKCS9_SIGNING_TIME = 13

    @property
    def type(self) -> Attribute.TYPE: ...

    def __str__(self) -> str: ...

class ContentType(Attribute):
    @property
    def oid(self) -> str: ...

class GenericType(Attribute):
    @property
    def oid(self) -> str: ...

    @property
    def raw_content(self) -> memoryview: ...

class MsSpcNestedSignature(Attribute):
    @property
    def signature(self) -> Signature: ...

class MsSpcStatementType(Attribute):
    @property
    def oid(self) -> str: ...

class MsManifestBinaryID(Attribute):
    manifest_id: str

    def __str__(self) -> str: ...

class PKCS9AtSequenceNumber(Attribute):
    @property
    def number(self) -> int: ...

class PKCS9CounterSignature(Attribute):
    @property
    def signer(self) -> SignerInfo: ...

class PKCS9MessageDigest(Attribute):
    @property
    def digest(self) -> bytes: ...

class PKCS9SigningTime(Attribute):
    @property
    def time(self) -> list[int]: ...

class SpcSpOpusInfo(Attribute):
    @property
    def program_name(self) -> Union[str, bytes]: ...

    @property
    def more_info(self) -> Union[str, bytes]: ...

class MsCounterSign(Attribute):
    class it_const_crt:
        def __getitem__(self, arg: int, /) -> x509: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> MsCounterSign.it_const_crt: ...

        def __next__(self) -> x509: ...

    class it_const_signers_t:
        def __getitem__(self, arg: int, /) -> SignerInfo: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> MsCounterSign.it_const_signers_t: ...

        def __next__(self) -> SignerInfo: ...

    @property
    def version(self) -> int: ...

    @property
    def digest_algorithm(self) -> ALGORITHMS: ...

    @property
    def content_info(self) -> ContentInfo: ...

    @property
    def certificates(self) -> MsCounterSign.it_const_crt: ...

    @property
    def signers(self) -> MsCounterSign.it_const_signers_t: ...

class SpcRelaxedPeMarkerCheck(Attribute):
    @property
    def value(self) -> int: ...

class SigningCertificateV2(Attribute):
    pass

class PKCS9TSTInfo(ContentInfo.Content):
    pass

class CHPEMetadata:
    class KIND(enum.Enum):
        UNKNOWN = 0

        ARM64 = 1

        X86 = 2

    @property
    def version(self) -> int: ...

    @property
    def kind(self) -> CHPEMetadata.KIND: ...

    def copy(self) -> Optional[CHPEMetadata]: ...

    def __str__(self) -> str: ...

class CHPEMetadataARM64(CHPEMetadata):
    class it_range_entries:
        def __getitem__(self, arg: int, /) -> CHPEMetadataARM64.range_entry_t: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> CHPEMetadataARM64.it_range_entries: ...

        def __next__(self) -> CHPEMetadataARM64.range_entry_t: ...

    class it_redirection_entries:
        def __getitem__(self, arg: int, /) -> CHPEMetadataARM64.redirection_entry_t: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> CHPEMetadataARM64.it_redirection_entries: ...

        def __next__(self) -> CHPEMetadataARM64.redirection_entry_t: ...

    class it_code_range_entry_point:
        def __getitem__(self, arg: int, /) -> CHPEMetadataARM64.code_range_entry_point_t: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> CHPEMetadataARM64.it_code_range_entry_point: ...

        def __next__(self) -> CHPEMetadataARM64.code_range_entry_point_t: ...

    class range_entry_t:
        class TYPE(enum.Enum):
            ARM64 = 0

            ARM64EC = 1

            AMD64 = 2

        start_offset: int

        length: int

        @property
        def type(self) -> CHPEMetadataARM64.range_entry_t.TYPE: ...

        @property
        def start(self) -> int: ...

        @property
        def end(self) -> int: ...

    class redirection_entry_t:
        src: int

        dst: int

    class code_range_entry_point_t:
        start_rva: int

        end_rva: int

        entrypoint: int

    code_map: int

    code_map_count: int

    code_ranges_to_entrypoints: int

    redirection_metadata: int

    os_arm64x_dispatch_call_no_redirect: int

    os_arm64x_dispatch_ret: int

    os_arm64x_dispatch_call: int

    os_arm64x_dispatch_icall: int

    os_arm64x_dispatch_icall_cfg: int

    alternate_entry_point: int

    auxiliary_iat: int

    code_ranges_to_entry_points_count: int

    redirection_metadata_count: int

    get_x64_information_function_pointer: int

    set_x64_information_function_pointer: int

    extra_rfe_table: int

    extra_rfe_table_size: int

    os_arm64x_dispatch_fptr: int

    auxiliary_iat_copy: int

    auxiliary_delay_import: int

    auxiliary_delay_import_copy: int

    bitfield_info: int

    @property
    def code_ranges(self) -> CHPEMetadataARM64.it_range_entries: ...

    @property
    def redirections(self) -> CHPEMetadataARM64.it_redirection_entries: ...

    @property
    def code_range_entry_point(self) -> CHPEMetadataARM64.it_code_range_entry_point: ...

class CHPEMetadataX86(CHPEMetadata):
    chpe_code_address_range_offset: int

    chpe_code_address_range_count: int

    wowa64_exception_handler_function_pointer: int

    wowa64_dispatch_call_function_pointer: int

    wowa64_dispatch_indirect_call_function_pointer: int

    wowa64_dispatch_indirect_call_cfg_function_pointer: int

    wowa64_dispatch_ret_function_pointer: int

    wowa64_dispatch_ret_leaf_function_pointer: int

    wowa64_dispatch_jump_function_pointer: int

    compiler_iat_pointer: int | None

    wowa64_rdtsc_function_pointer: int | None

class DynamicRelocation:
    class IMAGE_DYNAMIC_RELOCATION(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> DynamicRelocation.IMAGE_DYNAMIC_RELOCATION: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        RELOCATION_GUARD_RF_PROLOGUE = 1

        RELOCATION_GUARD_RF_EPILOGUE = 2

        RELOCATION_GUARD_IMPORT_CONTROL_TRANSFER = 3

        RELOCATION_GUARD_INDIR_CONTROL_TRANSFER = 4

        RELOCATION_GUARD_SWITCHTABLE_BRANCH = 5

        RELOCATION_ARM64X = 6

        RELOCATION_FUNCTION_OVERRIDE = 7

        RELOCATION_ARM64_KERNEL_IMPORT_CALL_TRANSFER = 8

    @property
    def version(self) -> int: ...

    symbol: int

    @property
    def fixups(self) -> DynamicFixup: ...

    def __str__(self) -> str: ...

    def copy(self) -> Optional[DynamicRelocation]: ...

class DynamicRelocationV1(DynamicRelocation):
    pass

class DynamicRelocationV2(DynamicRelocation):
    pass

class DynamicFixup:
    class KIND(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> DynamicFixup.KIND: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        GENERIC = 1

        ARM64X = 2

        FUNCTION_OVERRIDE = 3

        ARM64_KERNEL_IMPORT_CALL_TRANSFER = 4

    @property
    def kind(self) -> DynamicFixup.KIND: ...

    def __str__(self) -> str: ...

    def copy(self) -> Optional[DynamicFixup]: ...

class DynamicFixupARM64X(DynamicFixup):
    class FIXUP_TYPE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> DynamicFixupARM64X.FIXUP_TYPE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        ZEROFILL = 0

        VALUE = 1

        DELTA = 2

    class reloc_entry_t:
        rva: int

        type: DynamicFixupARM64X.FIXUP_TYPE

        size: int

        raw_bytes: list[int]

        value: int

        def __str__(self) -> str: ...

    class it_relocations:
        def __getitem__(self, arg: int, /) -> DynamicFixupARM64X.reloc_entry_t: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> DynamicFixupARM64X.it_relocations: ...

        def __next__(self) -> DynamicFixupARM64X.reloc_entry_t: ...

    @property
    def relocations(self) -> DynamicFixupARM64X.it_relocations: ...

class DynamicFixupControlTransfer(DynamicFixup):
    NO_IAT_INDEX: int = ...

    class it_relocations:
        def __getitem__(self, arg: int, /) -> DynamicFixupControlTransfer.reloc_entry_t: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> DynamicFixupControlTransfer.it_relocations: ...

        def __next__(self) -> DynamicFixupControlTransfer.reloc_entry_t: ...

    class reloc_entry_t:
        rva: int

        is_call: bool

        iat_index: int

        def __str__(self) -> str: ...

    @property
    def relocations(self) -> DynamicFixupControlTransfer.it_relocations: ...

class DynamicFixupARM64Kernel(DynamicFixup):
    NO_IAT_INDEX: int = ...

    class IMPORT_TYPE(enum.Enum):
        STATIC = 0

        DELAYED = 1

    class it_relocations:
        def __getitem__(self, arg: int, /) -> DynamicFixupARM64Kernel.reloc_entry_t: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> DynamicFixupARM64Kernel.it_relocations: ...

        def __next__(self) -> DynamicFixupARM64Kernel.reloc_entry_t: ...

    class reloc_entry_t:
        rva: int

        indirect_call: bool

        register_index: int

        import_type: DynamicFixupARM64Kernel.IMPORT_TYPE

        iat_index: int

        def __str__(self) -> str: ...

    @property
    def relocations(self) -> DynamicFixupARM64Kernel.it_relocations: ...

class DynamicFixupGeneric(DynamicFixup):
    class it_relocations:
        def __getitem__(self, arg: int, /) -> Relocation: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> DynamicFixupGeneric.it_relocations: ...

        def __next__(self) -> Relocation: ...

    @property
    def relocations(self) -> DynamicFixupGeneric.it_relocations: ...

class DynamicFixupUnknown(DynamicFixup):
    @property
    def payload(self) -> memoryview: ...

class FunctionOverrideInfo:
    class it_relocations:
        def __getitem__(self, arg: int, /) -> Relocation: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> DynamicFixupGeneric.it_relocations: ...

        def __next__(self) -> Relocation: ...

    original_rva: int

    bdd_offset: int

    @property
    def rva_size(self) -> int: ...

    @property
    def base_reloc_size(self) -> int: ...

    @property
    def relocations(self) -> DynamicFixupGeneric.it_relocations: ...

    @property
    def functions_rva(self) -> list[int]: ...

    def __str__(self) -> str: ...

class FunctionOverride(DynamicFixup):
    class image_bdd_dynamic_relocation_t:
        left: int

        right: int

        value: int

    class image_bdd_info_t:
        version: int

        original_size: int

        original_offset: int

        relocations: list[FunctionOverride.image_bdd_dynamic_relocation_t]

        payload: list[int]

    class it_func_overriding_info:
        def __getitem__(self, arg: int, /) -> FunctionOverrideInfo: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> FunctionOverride.it_func_overriding_info: ...

        def __next__(self) -> FunctionOverrideInfo: ...

    class it_bdd_info:
        def __getitem__(self, arg: int, /) -> FunctionOverride.image_bdd_info_t: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> FunctionOverride.it_bdd_info: ...

        def __next__(self) -> FunctionOverride.image_bdd_info_t: ...

    @property
    def func_overriding_info(self) -> FunctionOverride.it_func_overriding_info: ...

    @property
    def bdd_info(self) -> FunctionOverride.it_bdd_info: ...

    @overload
    def find_bdd_info(self, arg: int, /) -> FunctionOverride.image_bdd_info_t: ...

    @overload
    def find_bdd_info(self, arg: FunctionOverrideInfo, /) -> FunctionOverride.image_bdd_info_t: ...

class EnclaveImport:
    class TYPE(enum.Enum):
        NONE = 0

        UNIQUE_ID = 1

        AUTHOR_ID = 2

        FAMILY_ID = 3

        IMAGE_ID = 4

    type: EnclaveImport.TYPE

    min_security_version: int

    id: list[int]

    family_id: list[int]

    image_id: list[int]

    import_name_rva: int

    import_name: str

    reserved: int

    def __str__(self) -> str: ...

class EnclaveConfiguration:
    class it_imports:
        def __getitem__(self, arg: int, /) -> EnclaveImport: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> EnclaveConfiguration.it_imports: ...

        def __next__(self) -> EnclaveImport: ...

    size: int

    min_required_config_size: int

    policy_flags: int

    @property
    def is_debuggable(self) -> bool: ...

    import_list_rva: int

    import_entry_size: int

    @property
    def nb_imports(self) -> int: ...

    @property
    def imports(self) -> EnclaveConfiguration.it_imports: ...

    family_id: list[int]

    image_id: list[int]

    image_version: int

    security_version: int

    enclave_size: int

    nb_threads: int

    enclave_flags: int

    def __str__(self) -> str: ...

class VolatileMetadata:
    class range_t:
        start: int

        size: int

        @property
        def end(self) -> int: ...

    class it_info_ranges_t:
        def __getitem__(self, arg: int, /) -> VolatileMetadata.range_t: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> VolatileMetadata.it_info_ranges_t: ...

        def __next__(self) -> VolatileMetadata.range_t: ...

    size: int

    min_version: int

    max_version: int

    access_table_rva: int

    @property
    def access_table(self) -> list[int]: ...

    @property
    def access_table_size(self) -> int: ...

    info_range_rva: int

    @property
    def info_ranges_size(self) -> int: ...

    @property
    def info_ranges(self) -> VolatileMetadata.it_info_ranges_t: ...

    def __str__(self) -> str: ...

class LoadConfiguration(lief.Object):
    class guard_function_t:
        rva: int

        extra: int

    class it_guard_functions:
        def __getitem__(self, arg: int, /) -> LoadConfiguration.guard_function_t: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> LoadConfiguration.it_guard_functions: ...

        def __next__(self) -> LoadConfiguration.guard_function_t: ...

    class it_dynamic_relocations_t:
        def __getitem__(self, arg: int, /) -> DynamicRelocation: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> LoadConfiguration.it_dynamic_relocations_t: ...

        def __next__(self) -> DynamicRelocation: ...

    class IMAGE_GUARD(enum.Flag):
        @staticmethod
        def from_value(arg: int, /) -> LoadConfiguration.IMAGE_GUARD: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        NONE = 0

        CF_INSTRUMENTED = 256

        CFW_INSTRUMENTED = 512

        CF_FUNCTION_TABLE_PRESENT = 1024

        SECURITY_COOKIE_UNUSED = 2048

        PROTECT_DELAYLOAD_IAT = 4096

        DELAYLOAD_IAT_IN_ITS_OWN_SECTION = 8192

        CF_EXPORT_SUPPRESSION_INFO_PRESENT = 16384

        CF_ENABLE_EXPORT_SUPPRESSION = 32768

        CF_LONGJUMP_TABLE_PRESENT = 65536

        RF_INSTRUMENTED = 131072

        RF_ENABLE = 262144

        RF_STRICT = 524288

        RETPOLINE_PRESENT = 1048576

        EH_CONTINUATION_TABLE_PRESENT = 4194304

        XFG_ENABLED = 8388608

        CASTGUARD_PRESENT = 16777216

        MEMCPY_PRESENT = 33554432

    characteristics: int

    size: int

    timedatestamp: int

    major_version: int

    minor_version: int

    global_flags_clear: int

    global_flags_set: int

    critical_section_default_timeout: int

    decommit_free_block_threshold: int

    decommit_total_free_threshold: int

    lock_prefix_table: int

    maximum_allocation_size: int

    virtual_memory_threshold: int

    process_affinity_mask: int

    process_heap_flags: int

    csd_version: int

    dependent_load_flags: int

    reserved1: int

    editlist: int

    security_cookie: int

    se_handler_table: int | None

    @property
    def seh_functions(self) -> list[int]: ...

    se_handler_count: int | None

    guard_cf_check_function_pointer: int | None

    guard_cf_dispatch_function_pointer: int | None

    guard_cf_function_table: int | None

    guard_cf_function_count: int | None

    @property
    def guard_cf_functions(self) -> LoadConfiguration.it_guard_functions: ...

    guard_flags: int | None

    def has(self, arg: LoadConfiguration.IMAGE_GUARD, /) -> bool: ...

    @property
    def guard_cf_flags_list(self) -> list[LoadConfiguration.IMAGE_GUARD]: ...

    code_integrity: CodeIntegrity

    guard_address_taken_iat_entry_table: int | None

    guard_address_taken_iat_entry_count: int | None

    @property
    def guard_address_taken_iat_entries(self) -> LoadConfiguration.it_guard_functions: ...

    guard_long_jump_target_table: int | None

    guard_long_jump_target_count: int | None

    @property
    def guard_long_jump_targets(self) -> LoadConfiguration.it_guard_functions: ...

    dynamic_value_reloc_table: int | None

    hybrid_metadata_pointer: int | None

    @property
    def chpe_metadata_pointer(self) -> int | None: ...

    @property
    def chpe_metadata(self) -> CHPEMetadata: ...

    guard_rf_failure_routine: int | None

    guard_rf_failure_routine_function_pointer: int | None

    dynamic_value_reloctable_offset: int | None

    dynamic_value_reloctable_section: int | None

    @property
    def dynamic_relocations(self) -> LoadConfiguration.it_dynamic_relocations_t: ...

    reserved2: int | None

    guard_rf_verify_stackpointer_function_pointer: int | None

    hotpatch_table_offset: int | None

    reserved3: int | None

    enclave_configuration_ptr: int | None

    @property
    def enclave_config(self) -> EnclaveConfiguration: ...

    volatile_metadata_pointer: int | None

    @property
    def volatile_metadata(self) -> VolatileMetadata: ...

    guard_eh_continuation_table: int | None

    guard_eh_continuation_count: int | None

    @property
    def guard_eh_continuation_functions(self) -> LoadConfiguration.it_guard_functions: ...

    guard_xfg_check_function_pointer: int | None

    guard_xfg_dispatch_function_pointer: int | None

    guard_xfg_table_dispatch_function_pointer: int | None

    cast_guard_os_determined_failure_mode: int | None

    guard_memcpy_function_pointer: int | None

    uma_function_pointers: int | None

    def copy(self) -> LoadConfiguration: ...

    def __str__(self) -> str: ...

class Binary(lief.Binary):
    class it_section:
        def __getitem__(self, arg: int, /) -> Section: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_section: ...

        def __next__(self) -> Section: ...

    class it_data_directories:
        def __getitem__(self, arg: int, /) -> DataDirectory: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_data_directories: ...

        def __next__(self) -> DataDirectory: ...

    class it_relocations:
        def __getitem__(self, arg: int, /) -> Relocation: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> DynamicFixupGeneric.it_relocations: ...

        def __next__(self) -> Relocation: ...

    class it_imports:
        def __getitem__(self, arg: int, /) -> Import: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_imports: ...

        def __next__(self) -> Import: ...

    class it_delay_imports:
        def __getitem__(self, arg: int, /) -> DelayImport: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_delay_imports: ...

        def __next__(self) -> DelayImport: ...

    class it_symbols:
        def __getitem__(self, arg: int, /) -> lief.COFF.Symbol: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_symbols: ...

        def __next__(self) -> lief.COFF.Symbol: ...

    class it_const_signatures:
        def __getitem__(self, arg: int, /) -> Signature: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_const_signatures: ...

        def __next__(self) -> Signature: ...

    class it_debug:
        def __getitem__(self, arg: int, /) -> Debug: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_debug: ...

        def __next__(self) -> Debug: ...

    class it_strings_table:
        def __getitem__(self, arg: int, /) -> lief.COFF.String: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_strings_table: ...

        def __next__(self) -> lief.COFF.String: ...

    class it_exceptions:
        def __getitem__(self, arg: int, /) -> ExceptionInfo: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_exceptions: ...

        def __next__(self) -> ExceptionInfo: ...

    @property
    def sections(self) -> Binary.it_section: ... # type: ignore

    @property
    def dos_header(self) -> DosHeader: ...

    @property
    def header(self) -> Header: ... # type: ignore

    @property
    def optional_header(self) -> OptionalHeader: ...

    def compute_checksum(self) -> int: ...

    @property
    def virtual_size(self) -> int: ...

    @property
    def sizeof_headers(self) -> int: ...

    def rva_to_offset(self, rva_address: int) -> int: ...

    def va_to_offset(self, va_address: int) -> int: ...

    def section_from_offset(self, offset: int) -> Section: ...

    def section_from_rva(self, rva: int) -> Section: ...

    tls: TLS

    def remove_tls(self) -> None: ...

    rich_header: RichHeader

    @property
    def has_rich_header(self) -> bool: ...

    @property
    def has_debug(self) -> bool: ...

    @property
    def has_tls(self) -> bool: ...

    @property
    def has_imports(self) -> bool: ...

    @property
    def has_exports(self) -> bool: ...

    @property
    def has_resources(self) -> bool: ...

    @property
    def has_exceptions(self) -> bool: ...

    @property
    def has_relocations(self) -> bool: ...

    @property
    def has_configuration(self) -> bool: ...

    @property
    def has_signatures(self) -> bool: ...

    @property
    def is_reproducible_build(self) -> bool: ...

    @property
    def functions(self) -> list[lief.Function]: ...

    @property
    def exception_functions(self) -> list[lief.Function]: ...

    @property
    def signatures(self) -> Binary.it_const_signatures: ...

    def authentihash(self, algorithm: ALGORITHMS) -> bytes: ...

    @overload
    def verify_signature(self, checks: Signature.VERIFICATION_CHECKS = Signature.VERIFICATION_CHECKS.DEFAULT) -> Signature.VERIFICATION_FLAGS: ...

    @overload
    def verify_signature(self, signature: Signature, checks: Signature.VERIFICATION_CHECKS = Signature.VERIFICATION_CHECKS.DEFAULT) -> Signature.VERIFICATION_FLAGS: ...

    @property
    def authentihash_md5(self) -> bytes: ...

    @property
    def authentihash_sha1(self) -> bytes: ...

    @property
    def authentihash_sha256(self) -> bytes: ...

    @property
    def authentihash_sha512(self) -> bytes: ...

    @property
    def debug(self) -> Binary.it_debug: ...

    def add_debug_info(self, entry: Debug) -> Debug: ...

    def remove_debug(self, entry: Debug) -> bool: ...

    def clear_debug(self) -> bool: ...

    @property
    def codeview_pdb(self) -> CodeViewPDB: ...

    @property
    def load_configuration(self) -> LoadConfiguration: ...

    def get_export(self) -> Export: ...

    def set_export(self, arg: Export, /) -> Export: ...

    @property
    def symbols(self) -> Binary.it_symbols: ... # type: ignore

    def get_section(self, section_name: str) -> Section: ...

    def add_section(self, section: Section) -> Section: ...

    @property
    def relocations(self) -> DynamicFixupGeneric.it_relocations: ... # type: ignore

    def add_relocation(self, relocation: Relocation) -> Relocation: ...

    def remove_all_relocations(self) -> None: ...

    def remove(self, section: Section, clear: bool = False) -> None: ...

    @property
    def data_directories(self) -> Binary.it_data_directories: ...

    def data_directory(self, type: DataDirectory.TYPES) -> DataDirectory: ...

    @property
    def imports(self) -> Binary.it_imports: ...

    def has_import(self, import_name: str) -> bool: ...

    def get_import(self, import_name: str) -> Import: ...

    @property
    def delay_imports(self) -> Binary.it_delay_imports: ...

    @property
    def has_delay_imports(self) -> bool: ...

    def has_delay_import(self, import_name: str) -> bool: ...

    def get_delay_import(self, import_name: str) -> DelayImport: ...

    @property
    def resources_manager(self) -> Union[ResourcesManager, lief.lief_errors]: ...

    @property
    def resources(self) -> ResourceNode: ...

    @property
    def overlay(self) -> memoryview: ...

    @property
    def overlay_offset(self) -> int: ...

    dos_stub: memoryview

    def add_import(self, import_name: str) -> Import: ...

    def remove_import(self, name: str) -> bool: ...

    def remove_all_imports(self) -> None: ...

    def set_resources(self, new_tree: ResourceNode) -> ResourceNode: ...

    @property
    def exceptions(self) -> Binary.it_exceptions: ...

    @property
    def export_dir(self) -> DataDirectory: ...

    @property
    def import_dir(self) -> DataDirectory: ...

    @property
    def rsrc_dir(self) -> DataDirectory: ...

    @property
    def exceptions_dir(self) -> DataDirectory: ...

    @property
    def cert_dir(self) -> DataDirectory: ...

    @property
    def relocation_dir(self) -> DataDirectory: ...

    @property
    def debug_dir(self) -> DataDirectory: ...

    @property
    def tls_dir(self) -> DataDirectory: ...

    @property
    def load_config_dir(self) -> DataDirectory: ...

    @property
    def iat_dir(self) -> DataDirectory: ...

    @property
    def delay_dir(self) -> DataDirectory: ...

    @property
    def is_arm64ec(self) -> bool: ...

    @property
    def is_arm64x(self) -> bool: ...

    @overload
    def write(self, output_path: Union[str | os.PathLike]) -> None: ...

    @overload
    def write(self, output_path: Union[str | os.PathLike], config: Builder.config_t) -> None: ...

    @overload
    def write_to_bytes(self, config: Builder.config_t) -> bytes: ...

    @overload
    def write_to_bytes(self) -> bytes: ...

    def fill_address(self, address: int, size: int, value: int = 0, addr_type: lief.Binary.VA_TYPES = lief.Binary.VA_TYPES.AUTO) -> None: ...

    @property
    def coff_string_table(self) -> Binary.it_strings_table: ...

    def find_coff_string(self, offset: int) -> lief.COFF.String: ...

    def find_exception_at(self, rva: int) -> ExceptionInfo: ...

    @property
    def nested_pe_binary(self) -> Binary: ...

    def __str__(self) -> str: ...

class Builder:
    def __init__(self, binary: Binary, config: Builder.config_t) -> None: ...

    class config_t:
        def __init__(self) -> None: ...

        imports: bool

        exports: bool

        resources: bool

        relocations: bool

        load_configuration: bool

        tls: bool

        overlay: bool

        debug: bool

        dos_stub: bool

        rsrc_section: str

        idata_section: str

        tls_section: str

        reloc_section: str

        export_section: str

        debug_section: str

        resolved_iat_cbk: Callable[[Binary, Import, ImportEntry, int], None]

        force_relocating: bool

    @property
    def rsrc_data(self) -> memoryview: ...

    def build(self) -> Union[lief.ok_t, lief.lief_errors]: ...

    def write(self, output: str) -> None: ...

    def bytes(self) -> bytes: ...

class Factory:
    @staticmethod
    def create(arg: PE_TYPE, /) -> Optional[Factory]: ...

    def add_section(self, arg: Section, /) -> Factory: ...

    def get(self) -> Optional[Binary]: ...

class IMPHASH_MODE(enum.Enum):
    DEFAULT = 0

    LIEF = 0

    PEFILE = 1

    VT = 1

def oid_to_string(arg: str, /) -> str: ...

@overload
def get_type(file: Union[str | os.PathLike]) -> Union[PE_TYPE, lief.lief_errors]: ...

@overload
def get_type(raw: Sequence[int]) -> Union[PE_TYPE, lief.lief_errors]: ...

def get_imphash(binary: Binary, mode: IMPHASH_MODE = IMPHASH_MODE.DEFAULT) -> str: ...

def resolve_ordinals(imp: Import, strict: bool = False, use_std: bool = False) -> Union[Import, lief.lief_errors]: ...

def check_layout(binary: Binary) -> tuple[bool, str]: ...
