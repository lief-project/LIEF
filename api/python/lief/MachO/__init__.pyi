from collections.abc import Sequence
import enum
import io
import lief.MachO
import os
from typing import Iterator, Optional, Union, overload

import lief


class ARM64_RELOCATION(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> ARM64_RELOCATION: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    UNSIGNED = 0

    SUBTRACTOR = 1

    BRANCH26 = 2

    PAGE21 = 3

    PAGEOFF12 = 4

    GOT_LOAD_PAGE21 = 5

    GOT_LOAD_PAGEOFF12 = 6

    POINTER_TO_GOT = 7

    TLVP_LOAD_PAGE21 = 8

    TLVP_LOAD_PAGEOFF12 = 9

    ADDEND = 10

class ARM_RELOCATION(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> ARM_RELOCATION: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    VANILLA = 0

    PAIR = 1

    SECTDIFF = 2

    LOCAL_SECTDIFF = 3

    PB_LA_PTR = 4

    BR24 = 5

    THUMB_RELOC_BR22 = 6

    THUMB_32BIT_BRANCH = 7

    HALF = 8

    HALF_SECTDIFF = 9

class Binary(lief.Binary):
    class it_commands:
        def __getitem__(self, arg: int, /) -> LoadCommand: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_commands: ...

        def __next__(self) -> LoadCommand: ...

    class it_symbols:
        def __getitem__(self, arg: int, /) -> Symbol: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_symbols: ...

        def __next__(self) -> Symbol: ...

    class it_filter_symbols:
        def __getitem__(self, arg: int, /) -> Symbol: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_filter_symbols: ...

        def __next__(self) -> Symbol: ...

    class it_sections:
        def __getitem__(self, arg: int, /) -> Section: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_sections: ...

        def __next__(self) -> Section: ...

    class it_segments:
        def __getitem__(self, arg: int, /) -> SegmentCommand: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_segments: ...

        def __next__(self) -> SegmentCommand: ...

    class it_libraries:
        def __getitem__(self, arg: int, /) -> DylibCommand: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_libraries: ...

        def __next__(self) -> DylibCommand: ...

    class it_relocations:
        def __getitem__(self, arg: int, /) -> Relocation: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_relocations: ...

        def __next__(self) -> Relocation: ...

    class it_rpaths:
        def __getitem__(self, arg: int, /) -> RPathCommand: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_rpaths: ...

        def __next__(self) -> RPathCommand: ...

    class it_sub_clients:
        def __getitem__(self, arg: int, /) -> SubClient: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_sub_clients: ...

        def __next__(self) -> SubClient: ...

    class range_t:
        start: int

        end: int

    @property
    def header(self) -> Header: ... # type: ignore

    @property
    def sections(self) -> Binary.it_sections: ... # type: ignore

    @property
    def relocations(self) -> Binary.it_relocations: ... # type: ignore

    @property
    def segments(self) -> Binary.it_segments: ...

    @property
    def libraries(self) -> Binary.it_libraries: ... # type: ignore

    @property
    def symbols(self) -> Binary.it_symbols: ... # type: ignore

    def has_symbol(self, name: str) -> bool: ...

    def get_symbol(self, name: str) -> Symbol: ...

    @property
    def imported_symbols(self) -> Binary.it_filter_symbols: ...

    @property
    def exported_symbols(self) -> Binary.it_filter_symbols: ...

    @property
    def commands(self) -> Binary.it_commands: ...

    @property
    def filesets(self) -> FatBinary.it_binaries: ...

    @property
    def has_filesets(self) -> bool: ...

    @property
    def fileset_name(self) -> str: ...

    @property
    def imagebase(self) -> int: ...

    @property
    def virtual_size(self) -> int: ...

    @property
    def fat_offset(self) -> int: ...

    def section_from_offset(self, arg: int, /) -> Section: ...

    def section_from_virtual_address(self, arg: int, /) -> Section: ...

    def segment_from_offset(self, arg: int, /) -> SegmentCommand: ...

    def segment_from_virtual_address(self, arg: int, /) -> SegmentCommand: ...

    @property
    def has_entrypoint(self) -> bool: ...

    @property
    def has_uuid(self) -> bool: ...

    @property
    def uuid(self) -> UUIDCommand: ...

    @property
    def has_main_command(self) -> bool: ...

    @property
    def main_command(self) -> MainCommand: ...

    @property
    def has_dylinker(self) -> bool: ...

    @property
    def dylinker(self) -> DylinkerCommand: ...

    @property
    def has_dyld_info(self) -> bool: ...

    @property
    def dyld_info(self) -> DyldInfo: ...

    @property
    def has_function_starts(self) -> bool: ...

    @property
    def function_starts(self) -> FunctionStarts: ...

    @property
    def has_source_version(self) -> bool: ...

    @property
    def source_version(self) -> SourceVersion: ...

    @property
    def has_version_min(self) -> bool: ...

    @property
    def version_min(self) -> VersionMin: ...

    @property
    def has_routine_command(self) -> bool: ...

    @property
    def routine_command(self) -> Routine: ...

    @property
    def has_thread_command(self) -> bool: ...

    @property
    def thread_command(self) -> ThreadCommand: ...

    @property
    def has_rpath(self) -> bool: ...

    @property
    def rpath(self) -> RPathCommand: ...

    @property
    def rpaths(self) -> Binary.it_rpaths: ...

    @property
    def has_symbol_command(self) -> bool: ...

    @property
    def symbol_command(self) -> SymbolCommand: ...

    @property
    def has_dynamic_symbol_command(self) -> bool: ...

    @property
    def dynamic_symbol_command(self) -> DynamicSymbolCommand: ...

    @property
    def has_code_signature(self) -> bool: ...

    @property
    def code_signature(self) -> CodeSignature: ...

    @property
    def has_code_signature_dir(self) -> bool: ...

    @property
    def code_signature_dir(self) -> CodeSignatureDir: ...

    @property
    def has_data_in_code(self) -> bool: ...

    @property
    def data_in_code(self) -> DataInCode: ...

    @property
    def has_segment_split_info(self) -> bool: ...

    @property
    def segment_split_info(self) -> SegmentSplitInfo: ...

    @property
    def subclients(self) -> Binary.it_sub_clients: ...

    @property
    def has_subclients(self) -> bool: ...

    @property
    def has_sub_framework(self) -> bool: ...

    @property
    def sub_framework(self) -> SubFramework: ...

    @property
    def has_dyld_environment(self) -> bool: ...

    @property
    def dyld_environment(self) -> DyldEnvironment: ...

    @property
    def has_encryption_info(self) -> bool: ...

    @property
    def encryption_info(self) -> EncryptionInfo: ...

    @property
    def has_build_version(self) -> bool: ...

    @property
    def platform(self) -> BuildVersion.PLATFORMS: ...

    @property
    def is_ios(self) -> bool: ...

    @property
    def is_macos(self) -> bool: ...

    @property
    def build_version(self) -> BuildVersion: ...

    @property
    def has_dyld_chained_fixups(self) -> bool: ...

    @property
    def dyld_chained_fixups(self) -> DyldChainedFixups: ...

    @property
    def has_dyld_exports_trie(self) -> bool: ...

    @property
    def dyld_exports_trie(self) -> DyldExportsTrie: ...

    @property
    def has_two_level_hints(self) -> bool: ...

    @property
    def two_level_hints(self) -> TwoLevelHints: ...

    @property
    def has_linker_opt_hint(self) -> bool: ...

    @property
    def linker_opt_hint(self) -> LinkerOptHint: ...

    def virtual_address_to_offset(self, virtual_address: int) -> Union[int, lief.lief_errors]: ...

    def has_section(self, name: str) -> bool: ...

    @overload
    def get_section(self, name: str) -> Section: ...

    @overload
    def get_section(self, segname: str, secname: str) -> Section: ...

    def has_segment(self, name: str) -> bool: ...

    def get_segment(self, name: str) -> SegmentCommand: ...

    @property
    def va_ranges(self) -> Binary.range_t: ...

    @property
    def off_ranges(self) -> Binary.range_t: ...

    def is_valid_addr(self, address: int) -> bool: ...

    @overload
    def write(self, output: str) -> None: ...

    @overload
    def write(self, output: str, config: Builder.config_t) -> None: ...

    @overload
    def add(self, dylib_command: DylibCommand) -> LoadCommand: ...

    @overload
    def add(self, segment: SegmentCommand) -> LoadCommand: ...

    @overload
    def add(self, load_command: LoadCommand) -> LoadCommand: ...

    @overload
    def add(self, load_command: LoadCommand, index: int) -> LoadCommand: ...

    @overload
    def remove(self, load_command: LoadCommand) -> bool: ...

    @overload
    def remove(self, type: LoadCommand.TYPE) -> bool: ...

    @overload
    def remove(self, symbol: Symbol) -> bool: ...

    def remove_command(self, index: int) -> bool: ...

    @overload
    def remove_section(self, name: str, clear: bool = False) -> None: ...

    @overload
    def remove_section(self, segname: str, secname: str, clear: bool = False) -> None: ...

    def remove_signature(self) -> bool: ...

    def remove_symbol(self, name: str) -> bool: ...

    def can_remove(self, symbol: Symbol) -> bool: ...

    def can_remove_symbol(self, symbol_name: str) -> bool: ...

    @overload
    def unexport(self, name: str) -> bool: ...

    @overload
    def unexport(self, symbol: Symbol) -> bool: ...

    def extend(self, load_command: LoadCommand, size: int) -> bool: ...

    def extend_segment(self, segment_command: SegmentCommand, size: int) -> bool: ...

    @overload
    def add_section(self, segment: SegmentCommand, section: Section) -> Section: ...

    @overload
    def add_section(self, section: Section) -> Section: ...

    def add_library(self, library_name: str) -> LoadCommand: ...

    def get(self, type: LoadCommand.TYPE) -> LoadCommand: ...

    def has(self, type: LoadCommand.TYPE) -> bool: ...

    @property
    def unwind_functions(self) -> list[lief.Function]: ...

    @property
    def functions(self) -> list[lief.Function]: ...

    def shift(self, value: int) -> Union[lief.ok_t, lief.lief_errors]: ...

    def shift_linkedit(self, value: int) -> Union[lief.ok_t, lief.lief_errors]: ...

    def add_exported_function(self, address: int, name: str) -> ExportInfo: ...

    def add_local_symbol(self, address: int, name: str) -> Symbol: ...

    @property
    def page_size(self) -> int: ...

    @property
    def bindings(self) -> Iterator[BindingInfo]: ...

    @property
    def symbol_stubs(self) -> Sequence[Stub]: ...

    @property
    def has_nx_heap(self) -> bool: ...

    @property
    def has_nx_stack(self) -> bool: ...

    @property
    def support_arm64_ptr_auth(self) -> bool: ...

    @property
    def objc_metadata(self) -> Optional[lief.objc.Metadata]: ...

    def __getitem__(self, arg: LoadCommand.TYPE, /) -> LoadCommand: ...

    def __contains__(self, arg: LoadCommand.TYPE, /) -> bool: ...

    @property
    def overlay(self) -> memoryview: ...

    def __str__(self) -> str: ...

class BindingInfo(lief.Object):
    address: int

    library_ordinal: int

    addend: int

    weak_import: bool

    @property
    def has_library(self) -> bool: ...

    @property
    def library(self) -> DylibCommand: ...

    @property
    def has_segment(self) -> bool: ...

    @property
    def segment(self) -> SegmentCommand: ...

    @property
    def has_symbol(self) -> bool: ...

    @property
    def symbol(self) -> Symbol: ...

    def __str__(self) -> str: ...

class BuildToolVersion(lief.Object):
    @property
    def tool(self) -> BuildToolVersion.TOOLS: ...

    @property
    def version(self) -> list[int]: ...

    def __str__(self) -> str: ...

    class TOOLS(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> BuildToolVersion.TOOLS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        CLANG = 1

        SWIFT = 2

        LD = 3

        LLD = 4

class BuildVersion(LoadCommand):
    class PLATFORMS(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> BuildVersion.PLATFORMS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        MACOS = 1

        IOS = 2

        TVOS = 3

        WATCHOS = 4

        BRIDGEOS = 5

        MAC_CATALYST = 6

        IOS_SIMULATOR = 7

        TVOS_SIMULATOR = 8

        WATCHOS_SIMULATOR = 9

        DRIVERKIT = 10

        VISIONOS = 11

        VISIONOS_SIMULATOR = 12

        FIRMWARE = 13

        SEPOS = 14

        ANY = 4294967295

    platform: lief.MachO.BuildVersion.PLATFORMS

    minos: list[int]

    sdk: list[int]

    @property
    def tools(self) -> list[BuildToolVersion]: ...

    def __str__(self) -> str: ...

class Builder:
    class config_t:
        def __init__(self) -> None: ...

        linkedit: bool

    @overload
    @staticmethod
    def write(binary: Binary, output: str) -> Union[lief.ok_t, lief.lief_errors]: ...

    @overload
    @staticmethod
    def write(binary: Binary, output: str, config: Builder.config_t) -> Union[lief.ok_t, lief.lief_errors]: ...

    @overload
    @staticmethod
    def write(fat_binary: FatBinary, output: str) -> Union[lief.ok_t, lief.lief_errors]: ...

    @overload
    @staticmethod
    def write(fat_binary: FatBinary, output: str, config: Builder.config_t) -> Union[lief.ok_t, lief.lief_errors]: ...

class ChainedBindingInfo(BindingInfo):
    @property
    def format(self) -> DYLD_CHAINED_FORMAT: ...

    @property
    def ptr_format(self) -> DYLD_CHAINED_PTR_FORMAT: ...

    offset: int

    @property
    def sign_extended_addend(self) -> int: ...

    def __str__(self) -> str: ...

class ChainedPointerAnalysis:
    class dyld_chained_ptr_arm64e_rebase_t:
        @property
        def unpack_target(self) -> int: ...

        @property
        def target(self) -> int: ...

        @property
        def high8(self) -> int: ...

        @property
        def next(self) -> int: ...

        @property
        def bind(self) -> bool: ...

        @property
        def auth(self) -> bool: ...

        def __str__(self) -> str: ...

    class dyld_chained_ptr_arm64e_bind_t:
        @property
        def ordinal(self) -> int: ...

        @property
        def zero(self) -> int: ...

        @property
        def addend(self) -> int: ...

        @property
        def next(self) -> int: ...

        @property
        def bind(self) -> bool: ...

        @property
        def auth(self) -> bool: ...

        def __str__(self) -> str: ...

    class dyld_chained_ptr_arm64e_auth_rebase_t:
        @property
        def target(self) -> int: ...

        @property
        def diversity(self) -> int: ...

        @property
        def addr_div(self) -> int: ...

        @property
        def key(self) -> int: ...

        @property
        def next(self) -> int: ...

        @property
        def bind(self) -> bool: ...

        @property
        def auth(self) -> int: ...

        def __str__(self) -> str: ...

    class dyld_chained_ptr_arm64e_auth_bind_t:
        @property
        def ordinal(self) -> int: ...

        @property
        def zero(self) -> int: ...

        @property
        def diversity(self) -> int: ...

        @property
        def addr_div(self) -> int: ...

        @property
        def key(self) -> int: ...

        @property
        def next(self) -> int: ...

        @property
        def bind(self) -> bool: ...

        @property
        def auth(self) -> bool: ...

        def __str__(self) -> str: ...

    class dyld_chained_ptr_64_rebase_t:
        @property
        def unpack_target(self) -> int: ...

        @property
        def target(self) -> int: ...

        @property
        def high8(self) -> int: ...

        @property
        def reserved(self) -> int: ...

        @property
        def next(self) -> int: ...

        @property
        def bind(self) -> bool: ...

        def __str__(self) -> str: ...

    class dyld_chained_ptr_arm64e_bind24_t:
        @property
        def ordinal(self) -> int: ...

        @property
        def zero(self) -> int: ...

        @property
        def addend(self) -> int: ...

        @property
        def next(self) -> int: ...

        @property
        def bind(self) -> bool: ...

        @property
        def auth(self) -> bool: ...

        def __str__(self) -> str: ...

    class dyld_chained_ptr_arm64e_auth_bind24_t:
        @property
        def ordinal(self) -> int: ...

        @property
        def zero(self) -> int: ...

        @property
        def diversity(self) -> int: ...

        @property
        def addr_div(self) -> int: ...

        @property
        def key(self) -> int: ...

        @property
        def next(self) -> int: ...

        @property
        def bind(self) -> bool: ...

        @property
        def auth(self) -> bool: ...

        def __str__(self) -> str: ...

    class dyld_chained_ptr_64_bind_t:
        @property
        def ordinal(self) -> int: ...

        @property
        def addend(self) -> int: ...

        @property
        def reserved(self) -> int: ...

        @property
        def next(self) -> int: ...

        @property
        def bind(self) -> bool: ...

        def __str__(self) -> str: ...

    class dyld_chained_ptr_64_kernel_cache_rebase_t:
        @property
        def ordinal(self) -> int: ...

        @property
        def cache_level(self) -> int: ...

        @property
        def diversity(self) -> int: ...

        @property
        def addr_div(self) -> int: ...

        @property
        def key(self) -> int: ...

        @property
        def next(self) -> int: ...

        @property
        def is_auth(self) -> bool: ...

        def __str__(self) -> str: ...

    class dyld_chained_ptr_32_rebase_t:
        @property
        def target(self) -> int: ...

        @property
        def next(self) -> int: ...

        @property
        def bind(self) -> int: ...

        def __str__(self) -> str: ...

    class dyld_chained_ptr_32_bind_t:
        @property
        def ordinal(self) -> int: ...

        @property
        def addend(self) -> int: ...

        @property
        def next(self) -> int: ...

        @property
        def bind(self) -> bool: ...

        def __str__(self) -> str: ...

    class dyld_chained_ptr_32_cache_rebase_t:
        @property
        def target(self) -> int: ...

        @property
        def next(self) -> int: ...

        def __str__(self) -> str: ...

    class dyld_chained_ptr_32_firmware_rebase_t:
        @property
        def target(self) -> int: ...

        @property
        def next(self) -> int: ...

        def __str__(self) -> str: ...

    @staticmethod
    def stride(fmt: DYLD_CHAINED_PTR_FORMAT) -> int: ...

    @staticmethod
    def from_value(ptr: int, size: int) -> Optional[ChainedPointerAnalysis]: ...

    @property
    def value(self) -> int: ...

    @property
    def size(self) -> int: ...

    @property
    def dyld_chained_ptr_arm64e_rebase(self) -> ChainedPointerAnalysis.dyld_chained_ptr_arm64e_rebase_t: ...

    @property
    def dyld_chained_ptr_arm64e_bind(self) -> ChainedPointerAnalysis.dyld_chained_ptr_arm64e_bind_t: ...

    @property
    def dyld_chained_ptr_arm64e_auth_rebase(self) -> ChainedPointerAnalysis.dyld_chained_ptr_arm64e_auth_rebase_t: ...

    @property
    def dyld_chained_ptr_arm64e_auth_bind(self) -> ChainedPointerAnalysis.dyld_chained_ptr_arm64e_auth_bind_t: ...

    @property
    def dyld_chained_ptr_64_rebase(self) -> ChainedPointerAnalysis.dyld_chained_ptr_64_rebase_t: ...

    @property
    def dyld_chained_ptr_arm64e_bind24(self) -> ChainedPointerAnalysis.dyld_chained_ptr_arm64e_bind24_t: ...

    @property
    def dyld_chained_ptr_arm64e_auth_bind24(self) -> ChainedPointerAnalysis.dyld_chained_ptr_arm64e_auth_bind24_t: ...

    @property
    def dyld_chained_ptr_64_bind(self) -> ChainedPointerAnalysis.dyld_chained_ptr_64_bind_t: ...

    @property
    def dyld_chained_ptr_64_kernel_cache_rebase(self) -> ChainedPointerAnalysis.dyld_chained_ptr_64_kernel_cache_rebase_t: ...

    @property
    def dyld_chained_ptr_32_rebase(self) -> ChainedPointerAnalysis.dyld_chained_ptr_32_rebase_t: ...

    @property
    def dyld_chained_ptr_32_bind(self) -> ChainedPointerAnalysis.dyld_chained_ptr_32_bind_t: ...

    @property
    def dyld_chained_ptr_32_cache_rebase(self) -> ChainedPointerAnalysis.dyld_chained_ptr_32_cache_rebase_t: ...

    @property
    def dyld_chained_ptr_32_firmware_rebase(self) -> ChainedPointerAnalysis.dyld_chained_ptr_32_firmware_rebase_t: ...

    def get_as(self, arg: DYLD_CHAINED_PTR_FORMAT, /) -> Union[lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_arm64e_rebase_t, lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_arm64e_bind_t, lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_arm64e_auth_rebase_t, lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_arm64e_auth_bind_t, lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_64_rebase_t, lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_arm64e_bind24_t, lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_arm64e_auth_bind24_t, lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_64_bind_t, lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_64_kernel_cache_rebase_t, lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_32_rebase_t, lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_32_bind_t, lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_32_cache_rebase_t, lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_32_firmware_rebase_t, int, None]: ...

class CodeSignature(LoadCommand):
    data_offset: int

    data_size: int

    @property
    def content(self) -> memoryview: ...

    def __str__(self) -> str: ...

class CodeSignatureDir(LoadCommand):
    data_offset: int

    data_size: int

    @property
    def content(self) -> memoryview: ...

    def __str__(self) -> str: ...

class DYLD_CHAINED_FORMAT(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> DYLD_CHAINED_FORMAT: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    IMPORT = 1

    IMPORT_ADDEND = 2

    IMPORT_ADDEND64 = 3

class DYLD_CHAINED_PTR_FORMAT(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> DYLD_CHAINED_PTR_FORMAT: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    NONE = 0

    PTR_ARM64E = 1

    PTR_64 = 2

    PTR_32 = 3

    PTR_32_CACHE = 4

    PTR_32_FIRMWARE = 5

    PTR_64_OFFSET = 6

    PTR_ARM64E_KERNEL = 7

    PTR_64_KERNEL_CACHE = 8

    PTR_ARM64E_USERLAND = 9

    PTR_ARM64E_FIRMWARE = 10

    PTR_X86_64_KERNEL_CACHE = 11

    PTR_ARM64E_USERLAND24 = 12

class DataCodeEntry(lief.Object):
    class TYPES(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> DataCodeEntry.TYPES: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        DATA = 1

        JUMP_TABLE_8 = 2

        JUMP_TABLE_16 = 3

        JUMP_TABLE_32 = 4

        ABS_JUMP_TABLE_32 = 5

    offset: int

    length: int

    type: lief.MachO.DataCodeEntry.TYPES

    def __str__(self) -> str: ...

class DataInCode(LoadCommand):
    data_offset: int

    data_size: int

    @property
    def entries(self) -> it_data_in_code_entries: ...

    def add(self, entry: DataCodeEntry) -> DataInCode: ...

    @property
    def content(self) -> memoryview: ...

    def __str__(self) -> str: ...

class DyldBindingInfo(BindingInfo):
    class CLASS(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> DyldBindingInfo.CLASS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        WEAK = 1

        LAZY = 2

        STANDARD = 3

        THREADED = 100

    class TYPE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> DyldBindingInfo.TYPE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        POINTER = 1

        TEXT_ABSOLUTE32 = 2

        TEXT_PCREL32 = 3

    binding_class: lief.MachO.DyldBindingInfo.CLASS

    binding_type: lief.MachO.DyldBindingInfo.TYPE

    @property
    def original_offset(self) -> int: ...

    def __str__(self) -> str: ...

class DyldChainedFixups(LoadCommand):
    class it_binding_info:
        def __getitem__(self, arg: int, /) -> ChainedBindingInfo: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> DyldChainedFixups.it_binding_info: ...

        def __next__(self) -> ChainedBindingInfo: ...

    class it_chained_starts_in_segments_t:
        def __getitem__(self, arg: int, /) -> DyldChainedFixups.chained_starts_in_segment: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> DyldChainedFixups.it_chained_starts_in_segments_t: ...

        def __next__(self) -> DyldChainedFixups.chained_starts_in_segment: ...

    class chained_starts_in_segment:
        @property
        def offset(self) -> int: ...

        @property
        def size(self) -> int: ...

        @property
        def page_size(self) -> int: ...

        @property
        def segment_offset(self) -> int: ...

        @property
        def page_start(self) -> list[int]: ...

        @property
        def pointer_format(self) -> DYLD_CHAINED_PTR_FORMAT: ...

        @property
        def max_valid_pointer(self) -> int: ...

        @property
        def page_count(self) -> int: ...

        @property
        def segment(self) -> SegmentCommand: ...

        def __str__(self) -> str: ...

    data_offset: int

    data_size: int

    @property
    def payload(self) -> memoryview: ...

    @property
    def bindings(self) -> DyldChainedFixups.it_binding_info: ...

    @property
    def chained_starts_in_segments(self) -> DyldChainedFixups.it_chained_starts_in_segments_t: ...

    fixups_version: int

    starts_offset: int

    imports_offset: int

    symbols_offset: int

    imports_count: int

    symbols_format: int

    imports_format: lief.MachO.DYLD_CHAINED_FORMAT

    def __str__(self) -> str: ...

class DyldEnvironment(LoadCommand):
    value: str

    def __str__(self) -> str: ...

class DyldExportsTrie(LoadCommand):
    class it_export_info:
        def __getitem__(self, arg: int, /) -> ExportInfo: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> DyldExportsTrie.it_export_info: ...

        def __next__(self) -> ExportInfo: ...

    data_offset: int

    data_size: int

    @property
    def content(self) -> memoryview: ...

    @property
    def exports(self) -> DyldExportsTrie.it_export_info: ...

    def show_export_trie(self) -> str: ...

    def __str__(self) -> str: ...

class DyldInfo(LoadCommand):
    class REBASE_TYPE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> DyldInfo.REBASE_TYPE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        POINTER = 1

        TEXT_ABSOLUTE32 = 2

        TEXT_PCREL32 = 3

        THREADED = 102

    class REBASE_OPCODES(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> DyldInfo.REBASE_OPCODES: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        DONE = 0

        SET_TYPE_IMM = 16

        SET_SEGMENT_AND_OFFSET_ULEB = 32

        ADD_ADDR_ULEB = 48

        ADD_ADDR_IMM_SCALED = 64

        DO_REBASE_IMM_TIMES = 80

        DO_REBASE_ULEB_TIMES = 96

        DO_REBASE_ADD_ADDR_ULEB = 112

        DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = 128

    class BIND_OPCODES(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> DyldInfo.BIND_OPCODES: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        DONE = 0

        SET_DYLIB_ORDINAL_IMM = 16

        SET_DYLIB_ORDINAL_ULEB = 32

        SET_DYLIB_SPECIAL_IMM = 48

        SET_SYMBOL_TRAILING_FLAGS_IMM = 64

        SET_TYPE_IMM = 80

        SET_ADDEND_SLEB = 96

        SET_SEGMENT_AND_OFFSET_ULEB = 112

        ADD_ADDR_ULEB = 128

        DO_BIND = 144

        DO_BIND_ADD_ADDR_ULEB = 160

        DO_BIND_ADD_ADDR_IMM_SCALED = 176

        DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 192

        THREADED_APPLY = 209

        THREADED = 208

    class it_binding_info:
        def __getitem__(self, arg: int, /) -> DyldBindingInfo: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> DyldInfo.it_binding_info: ...

        def __next__(self) -> DyldBindingInfo: ...

    class it_export_info:
        def __getitem__(self, arg: int, /) -> ExportInfo: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> DyldInfo.it_export_info: ...

        def __next__(self) -> ExportInfo: ...

    rebase: tuple[int, int]

    rebase_opcodes: memoryview

    @property
    def show_rebases_opcodes(self) -> str: ...

    bind: tuple[int, int]

    bind_opcodes: memoryview

    @property
    def show_bind_opcodes(self) -> str: ...

    weak_bind: tuple[int, int]

    weak_bind_opcodes: memoryview

    @property
    def show_weak_bind_opcodes(self) -> str: ...

    lazy_bind: tuple[int, int]

    lazy_bind_opcodes: memoryview

    @property
    def show_lazy_bind_opcodes(self) -> str: ...

    @property
    def bindings(self) -> DyldInfo.it_binding_info: ...

    export_info: tuple[int, int]

    export_trie: memoryview

    @property
    def exports(self) -> DyldExportsTrie.it_export_info: ...

    @property
    def show_export_trie(self) -> str: ...

    def set_rebase_offset(self, offset: int) -> None: ...

    def set_rebase_size(self, size: int) -> None: ...

    def set_bind_offset(self, offset: int) -> None: ...

    def set_bind_size(self, size: int) -> None: ...

    def set_weak_bind_offset(self, offset: int) -> None: ...

    def set_weak_bind_size(self, size: int) -> None: ...

    def set_lazy_bind_offset(self, offset: int) -> None: ...

    def set_lazy_bind_size(self, size: int) -> None: ...

    def set_export_offset(self, offset: int) -> None: ...

    def set_export_size(self, size: int) -> None: ...

    def __str__(self) -> str: ...

class DylibCommand(LoadCommand):
    name: str

    timestamp: int

    current_version: list[int]

    compatibility_version: list[int]

    @staticmethod
    def weak_lib(name: str, timestamp: int = 0, current_version: int = 0, compat_version: int = 0) -> DylibCommand: ...

    @staticmethod
    def id_dylib(name: str, timestamp: int = 0, current_version: int = 0, compat_version: int = 0) -> DylibCommand: ...

    @staticmethod
    def load_dylib(name: str, timestamp: int = 0, current_version: int = 0, compat_version: int = 0) -> DylibCommand: ...

    @staticmethod
    def reexport_dylib(name: str, timestamp: int = 0, current_version: int = 0, compat_version: int = 0) -> DylibCommand: ...

    @staticmethod
    def load_upward_dylib(name: str, timestamp: int = 0, current_version: int = 0, compat_version: int = 0) -> DylibCommand: ...

    @staticmethod
    def lazy_load_dylib(name: str, timestamp: int = 0, current_version: int = 0, compat_version: int = 0) -> DylibCommand: ...

    def __str__(self) -> str: ...

class DylinkerCommand(LoadCommand):
    def __init__(self, arg: str, /) -> None: ...

    name: str

    def __str__(self) -> str: ...

class DynamicSymbolCommand(LoadCommand):
    class it_indirect_symbols:
        def __getitem__(self, arg: int, /) -> Symbol: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> DynamicSymbolCommand.it_indirect_symbols: ...

        def __next__(self) -> Symbol: ...

    idx_local_symbol: int

    nb_local_symbols: int

    idx_external_define_symbol: int

    nb_external_define_symbols: int

    idx_undefined_symbol: int

    nb_undefined_symbols: int

    toc_offset: int

    nb_toc: int

    module_table_offset: int

    nb_module_table: int

    external_reference_symbol_offset: int

    nb_external_reference_symbols: int

    indirect_symbol_offset: int

    nb_indirect_symbols: int

    external_relocation_offset: int

    nb_external_relocations: int

    local_relocation_offset: int

    nb_local_relocations: int

    @property
    def indirect_symbols(self) -> DynamicSymbolCommand.it_indirect_symbols: ...

    def __str__(self) -> str: ...

class EncryptionInfo(LoadCommand):
    crypt_offset: int

    crypt_size: int

    crypt_id: int

    def __str__(self) -> str: ...

class ExportInfo(lief.Object):
    class KIND(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> ExportInfo.KIND: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        REGULAR = 0

        THREAD_LOCAL_KIND = 1

        ABSOLUTE_KIND = 2

    class FLAGS(enum.Flag):
        @staticmethod
        def from_value(arg: int, /) -> ExportInfo.FLAGS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        WEAK_DEFINITION = 4

        REEXPORT = 8

        STUB_AND_RESOLVER = 16

    @property
    def node_offset(self) -> int: ...

    @property
    def kind(self) -> ExportInfo.KIND: ...

    @property
    def flags_list(self) -> list[ExportInfo.FLAGS]: ...

    flags: int

    address: int

    @property
    def alias(self) -> Symbol: ...

    @property
    def alias_library(self) -> DylibCommand: ...

    @property
    def has_symbol(self) -> bool: ...

    def has(self, flag: ExportInfo.FLAGS) -> bool: ...

    @property
    def symbol(self) -> Symbol: ...

    def __str__(self) -> str: ...

class FatBinary:
    class it_binaries:
        def __getitem__(self, arg: int, /) -> Binary: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> FatBinary.it_binaries: ...

        def __next__(self) -> Binary: ...

    @property
    def size(self) -> int: ...

    def at(self, index: int) -> Binary: ...

    def take(self, cpu: Header.CPU_TYPE) -> Optional[Binary]: ...

    def write(self, filename: str) -> None: ...

    def raw(self) -> list[int]: ...

    def __len__(self) -> int: ...

    def __getitem__(self, arg: int, /) -> Binary: ...

    def __iter__(self) -> FatBinary.it_binaries: ...

    def __str__(self) -> str: ...

class FilesetCommand(LoadCommand):
    name: str

    virtual_address: int

    file_offset: int

    @property
    def binary(self) -> Binary: ...

    def __str__(self) -> str: ...

class FunctionStarts(LoadCommand):
    data_offset: int

    data_size: int

    functions: list[int]

    def add_function(self, address: int) -> None: ...

    @property
    def content(self) -> memoryview: ...

    def __str__(self) -> str: ...

class Header(lief.Object):
    def __init__(self) -> None: ...

    class CPU_TYPE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Header.CPU_TYPE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        ANY = -1

        X86 = 7

        X86_64 = 16777223

        MIPS = 8

        MC98000 = 10

        ARM = 12

        ARM64 = 16777228

        SPARC = 14

        POWERPC = 18

        POWERPC64 = 16777234

    class FILE_TYPE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Header.FILE_TYPE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        OBJECT = 1

        EXECUTE = 2

        FVMLIB = 3

        CORE = 4

        PRELOAD = 5

        DYLIB = 6

        DYLINKER = 7

        BUNDLE = 8

        DYLIB_STUB = 9

        DSYM = 10

        KEXT_BUNDLE = 11

    class FLAGS(enum.Flag):
        @staticmethod
        def from_value(arg: int, /) -> Header.FLAGS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        NOUNDEFS = 1

        INCRLINK = 2

        DYLDLINK = 4

        BINDATLOAD = 8

        PREBOUND = 16

        SPLIT_SEGS = 32

        LAZY_INIT = 64

        TWOLEVEL = 128

        FORCE_FLAT = 256

        NOMULTIDEFS = 512

        NOFIXPREBINDING = 1024

        PREBINDABLE = 2048

        ALLMODSBOUND = 4096

        SUBSECTIONS_VIA_SYMBOLS = 8192

        CANONICAL = 16384

        WEAK_DEFINES = 32768

        BINDS_TO_WEAK = 65536

        ALLOW_STACK_EXECUTION = 131072

        ROOT_SAFE = 262144

        SETUID_SAFE = 524288

        NO_REEXPORTED_DYLIBS = 1048576

        PIE = 2097152

        DEAD_STRIPPABLE_DYLIB = 4194304

        HAS_TLV_DESCRIPTORS = 8388608

        NO_HEAP_EXECUTION = 16777216

        APP_EXTENSION_SAFE = 33554432

    magic: lief.MachO.MACHO_TYPES

    cpu_type: lief.MachO.Header.CPU_TYPE

    cpu_subtype: int

    file_type: lief.MachO.Header.FILE_TYPE

    flags: int

    nb_cmds: int

    sizeof_cmds: int

    reserved: int

    @property
    def flags_list(self) -> list[Header.FLAGS]: ...

    def add(self, flag: Header.FLAGS) -> None: ...

    def remove(self, flag: Header.FLAGS) -> None: ...

    def has(self, flag: Header.FLAGS) -> bool: ...

    def __iadd__(self, arg: Header.FLAGS, /) -> Header: ...

    def __isub__(self, arg: Header.FLAGS, /) -> Header: ...

    def __contains__(self, arg: Header.FLAGS, /) -> bool: ...

    def __str__(self) -> str: ...

class IndirectBindingInfo(BindingInfo):
    pass

class LinkEdit(SegmentCommand):
    pass

class LinkerOptHint(LoadCommand):
    data_offset: int

    data_size: int

    @property
    def content(self) -> memoryview: ...

    def __str__(self) -> str: ...

class LoadCommand(lief.Object):
    def __init__(self) -> None: ...

    class TYPE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> LoadCommand.TYPE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        SEGMENT = 1

        SYMTAB = 2

        SYMSEG = 3

        THREAD = 4

        UNIXTHREAD = 5

        LOADFVMLIB = 6

        IDFVMLIB = 7

        IDENT = 8

        FVMFILE = 9

        PREPAGE = 10

        DYSYMTAB = 11

        LOAD_DYLIB = 12

        ID_DYLIB = 13

        LOAD_DYLINKER = 14

        ID_DYLINKER = 15

        PREBOUND_DYLIB = 16

        ROUTINES = 17

        SUB_FRAMEWORK = 18

        SUB_UMBRELLA = 19

        SUB_CLIENT = 20

        SUB_LIBRARY = 21

        TWOLEVEL_HINTS = 22

        PREBIND_CKSUM = 23

        LOAD_WEAK_DYLIB = 2147483672

        SEGMENT_64 = 25

        ROUTINES_64 = 26

        UUID = 27

        RPATH = 2147483676

        CODE_SIGNATURE = 29

        SEGMENT_SPLIT_INFO = 30

        REEXPORT_DYLIB = 2147483679

        LAZY_LOAD_DYLIB = 32

        ENCRYPTION_INFO = 33

        DYLD_INFO = 34

        DYLD_INFO_ONLY = 2147483682

        LOAD_UPWARD_DYLIB = 2147483683

        VERSION_MIN_MACOSX = 36

        VERSION_MIN_IPHONEOS = 37

        FUNCTION_STARTS = 38

        DYLD_ENVIRONMENT = 39

        MAIN = 2147483688

        DATA_IN_CODE = 41

        SOURCE_VERSION = 42

        DYLIB_CODE_SIGN_DRS = 43

        ENCRYPTION_INFO_64 = 44

        LINKER_OPTION = 45

        LINKER_OPTIMIZATION_HINT = 46

        VERSION_MIN_TVOS = 47

        VERSION_MIN_WATCHOS = 48

        NOTE = 49

        BUILD_VERSION = 50

        DYLD_EXPORTS_TRIE = 2147483699

        DYLD_CHAINED_FIXUPS = 2147483700

        FILESET_ENTRY = 2147483701

        LIEF_UNKNOWN = 4293787649

    command: lief.MachO.LoadCommand.TYPE

    size: int

    data: memoryview

    command_offset: int

    def __str__(self) -> str: ...

class MACHO_TYPES(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> MACHO_TYPES: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    MAGIC = 4277009102

    CIGAM = 3472551422

    MAGIC_64 = 4277009103

    CIGAM_64 = 3489328638

    FAT_MAGIC = 3405691582

    FAT_CIGAM = 3199925962

    NEURAL_MODEL = 3203398350

class MainCommand(LoadCommand):
    def __init__(self, arg0: int, arg1: int, /) -> None: ...

    entrypoint: int

    stack_size: int

    def __str__(self) -> str: ...

class PPC_RELOCATION(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> PPC_RELOCATION: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    VANILLA = 0

    PAIR = 1

    BR14 = 2

    BR24 = 3

    HI16 = 4

    LO16 = 5

    HA16 = 6

    LO14 = 7

    SECTDIFF = 8

    PB_LA_PTR = 9

    HI16_SECTDIFF = 10

    LO16_SECTDIFF = 11

    HA16_SECTDIFF = 12

    JBSR = 13

    LO14_SECTDIFF = 14

    LOCAL_SECTDIFF = 15

class ParserConfig:
    def __init__(self) -> None: ...

    parse_dyld_exports: bool

    parse_dyld_bindings: bool

    parse_dyld_rebases: bool

    fix_from_memory: bool

    from_dyld_shared_cache: bool

    def full_dyldinfo(self, flag: bool) -> ParserConfig: ...

    deep: lief.MachO.ParserConfig = ...

    quick: lief.MachO.ParserConfig = ...

class RPathCommand(LoadCommand):
    @staticmethod
    def create(path: str) -> Optional[RPathCommand]: ...

    path: str

    def __str__(self) -> str: ...

class Relocation(lief.Relocation):
    class ORIGIN(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Relocation.ORIGIN: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        DYLDINFO = 1

        RELOC_TABLE = 2

        CHAINED_FIXUPS = 3

    address: int

    pc_relative: bool

    type: Union[lief.MachO.X86_RELOCATION, lief.MachO.X86_64_RELOCATION, lief.MachO.PPC_RELOCATION, lief.MachO.ARM_RELOCATION, lief.MachO.ARM64_RELOCATION, lief.MachO.DyldInfo.REBASE_TYPE, ]

    @property
    def architecture(self) -> Header.CPU_TYPE: ...

    @property
    def has_symbol(self) -> bool: ...

    @property
    def symbol(self) -> Symbol: ...

    @property
    def has_section(self) -> bool: ...

    @property
    def section(self) -> Section: ...

    @property
    def origin(self) -> Relocation.ORIGIN: ...

    @property
    def has_segment(self) -> bool: ...

    @property
    def segment(self) -> SegmentCommand: ...

    def __str__(self) -> str: ...

class RelocationDyld(Relocation):
    def __le__(self, arg: RelocationDyld, /) -> bool: ...

    def __lt__(self, arg: RelocationDyld, /) -> bool: ...

    def __ge__(self, arg: RelocationDyld, /) -> bool: ...

    def __gt__(self, arg: RelocationDyld, /) -> bool: ...

    def __str__(self) -> str: ...

class RelocationFixup(Relocation):
    target: int

    next: int

    def __str__(self) -> str: ...

class RelocationObject(Relocation):
    value: int

    @property
    def is_scattered(self) -> bool: ...

    def __str__(self) -> str: ...

class Routine(LoadCommand):
    init_address: int

    init_module: int

    reserved1: int

    reserved2: int

    reserved3: int

    reserved4: int

    reserved5: int

    reserved6: int

    def __str__(self) -> str: ...

class Section(lief.Section):
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, section_name: str) -> None: ...

    @overload
    def __init__(self, section_name: str, content: Sequence[int]) -> None: ...

    class it_relocations:
        def __getitem__(self, arg: int, /) -> Relocation: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Section.it_relocations: ...

        def __next__(self) -> Relocation: ...

    class TYPE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Section.TYPE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        REGULAR = 0

        ZEROFILL = 1

        CSTRING_LITERALS = 2

        S_4BYTE_LITERALS = 3

        S_8BYTE_LITERALS = 4

        LITERAL_POINTERS = 5

        NON_LAZY_SYMBOL_POINTERS = 6

        LAZY_SYMBOL_POINTERS = 7

        SYMBOL_STUBS = 8

        MOD_INIT_FUNC_POINTERS = 9

        MOD_TERM_FUNC_POINTERS = 10

        COALESCED = 11

        GB_ZEROFILL = 12

        INTERPOSING = 13

        S_16BYTE_LITERALS = 14

        DTRACE_DOF = 15

        LAZY_DYLIB_SYMBOL_POINTERS = 16

        THREAD_LOCAL_REGULAR = 17

        THREAD_LOCAL_ZEROFILL = 18

        THREAD_LOCAL_VARIABLES = 19

        THREAD_LOCAL_VARIABLE_POINTERS = 20

        THREAD_LOCAL_INIT_FUNCTION_POINTERS = 21

        INIT_FUNC_OFFSETS = 22

    class FLAGS(enum.Flag):
        @staticmethod
        def from_value(arg: int, /) -> Section.FLAGS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        PURE_INSTRUCTIONS = 2147483648

        NO_TOC = 1073741824

        STRIP_STATIC_SYMS = 536870912

        NO_DEAD_STRIP = 268435456

        LIVE_SUPPORT = 134217728

        SELF_MODIFYING_CODE = 67108864

        DEBUG_INFO = 33554432

        SOME_INSTRUCTIONS = 1024

        EXT_RELOC = 512

        LOC_RELOC = 256

    alignment: int

    relocation_offset: int

    numberof_relocations: int

    type: lief.MachO.Section.TYPE

    @property
    def relocations(self) -> SegmentCommand.it_relocations: ...

    reserved1: int

    reserved2: int

    reserved3: int

    flags: lief.MachO.Section.FLAGS

    @property
    def flags_list(self) -> list[Section.FLAGS]: ...

    @property
    def segment(self) -> SegmentCommand: ...

    segment_name: str

    @property
    def has_segment(self) -> bool: ...

    def has(self, flag: Section.FLAGS) -> bool: ...

    def add(self, flag: Section.FLAGS) -> None: ...

    def remove(self, flag: Section.FLAGS) -> None: ...

    def __iadd__(self, arg: Section.FLAGS, /) -> Section: ...

    def __isub__(self, arg: Section.FLAGS, /) -> Section: ...

    def __contains__(self, arg: Section.FLAGS, /) -> bool: ...

    def __str__(self) -> str: ...

class SegmentCommand(LoadCommand):
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, arg: str, /) -> None: ...

    @overload
    def __init__(self, arg0: str, arg1: Sequence[int], /) -> None: ...

    class it_sections:
        def __getitem__(self, arg: int, /) -> Section: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> SegmentCommand.it_sections: ...

        def __next__(self) -> Section: ...

    class it_relocations:
        def __getitem__(self, arg: int, /) -> Relocation: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> SegmentCommand.it_relocations: ...

        def __next__(self) -> Relocation: ...

    class VM_PROTECTIONS(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> SegmentCommand.VM_PROTECTIONS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        R = 1

        W = 2

        X = 4

    class FLAGS(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> SegmentCommand.FLAGS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        HIGHVM = 1

        FVMLIB = 2

        NORELOC = 4

        PROTECTED_VERSION_1 = 8

        READ_ONLY = 16

    name: Union[str, bytes]

    virtual_address: int

    virtual_size: int

    file_size: int

    file_offset: int

    max_protection: int

    init_protection: int

    numberof_sections: int

    @property
    def sections(self) -> SegmentCommand.it_sections: ...

    @property
    def relocations(self) -> SegmentCommand.it_relocations: ...

    @property
    def index(self) -> int: ...

    content: memoryview

    flags: int

    def has(self, section: Section) -> bool: ...

    def has_section(self, section_name: str) -> bool: ...

    def add_section(self, section: Section) -> Section: ...

    def get_section(self, name: str) -> Section: ...

    def __str__(self) -> str: ...

class SegmentSplitInfo(LoadCommand):
    data_offset: int

    data_size: int

    @property
    def content(self) -> memoryview: ...

    def __str__(self) -> str: ...

class SourceVersion(LoadCommand):
    version: list[int]

    def __str__(self) -> str: ...

class Stub:
    def __init__(self, target_info: Stub.target_info_t, address: int, raw_stub: Sequence[int]) -> None: ...

    class target_info_t:
        @overload
        def __init__(self) -> None: ...

        @overload
        def __init__(self, arg0: Header.CPU_TYPE, arg1: int, /) -> None: ...

        arch: lief.MachO.Header.CPU_TYPE

        subtype: int

    @property
    def address(self) -> int: ...

    @property
    def raw(self) -> memoryview: ...

    @property
    def target(self) -> Union[int, lief.lief_errors]: ...

    def __str__(self) -> str: ...

class SubClient(LoadCommand):
    client: str

    def __str__(self) -> str: ...

class SubFramework(LoadCommand):
    umbrella: str

    def __str__(self) -> str: ...

class Symbol(lief.Symbol):
    def __init__(self) -> None: ...

    class CATEGORY(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Symbol.CATEGORY: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        NONE = 0

        LOCAL = 1

        EXTERNAL = 2

        UNDEFINED = 3

        INDIRECT_ABS = 4

        INDIRECT_LOCAL = 5

        INDIRECT_ABS_LOCAL = 6

    class ORIGIN(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Symbol.ORIGIN: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        DYLD_EXPORT = 1

        DYLD_BIND = 2

        LC_SYMTAB = 3

    class TYPE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Symbol.TYPE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNDEFINED = 0

        ABSOLUTE_SYM = 2

        SECTION = 14

        PREBOUND = 12

        INDIRECT = 10

    @property
    def demangled_name(self) -> str: ...

    @property
    def category(self) -> Symbol.CATEGORY: ...

    raw_type: int

    @property
    def type(self) -> Symbol.TYPE: ...

    numberof_sections: int

    description: int

    @property
    def has_export_info(self) -> bool: ...

    @property
    def origin(self) -> Symbol.ORIGIN: ...

    @property
    def export_info(self) -> ExportInfo: ...

    @property
    def has_binding_info(self) -> bool: ...

    @property
    def binding_info(self) -> BindingInfo: ...

    @property
    def library(self) -> DylibCommand: ...

    @property
    def is_external(self) -> bool: ...

    @property
    def library_ordinal(self) -> int: ...

    def __str__(self) -> str: ...

class SymbolCommand(LoadCommand):
    def __init__(self) -> None: ...

    symbol_offset: int

    numberof_symbols: int

    strings_offset: int

    strings_size: int

    def __str__(self) -> str: ...

class ThreadCommand(LoadCommand):
    def __init__(self, arg0: int, arg1: int, arg2: Header.CPU_TYPE, /) -> None: ...

    flavor: int

    state: memoryview

    count: int

    @property
    def pc(self) -> int: ...

    architecture: lief.MachO.Header.CPU_TYPE

    def __str__(self) -> str: ...

class TwoLevelHints(LoadCommand):
    class it_hints_t:
        def __getitem__(self, arg: int, /) -> int: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> TwoLevelHints.it_hints_t: ...

        def __next__(self) -> int: ...

    @property
    def hints(self) -> TwoLevelHints.it_hints_t: ...

    @property
    def content(self) -> memoryview: ...

    def __str__(self) -> str: ...

class UUIDCommand(LoadCommand):
    uuid: list[int]

    def __str__(self) -> str: ...

class UnknownCommand(LoadCommand):
    @property
    def original_command(self) -> int: ...

    def __str__(self) -> str: ...

class VersionMin(LoadCommand):
    version: list[int]

    sdk: list[int]

    def __str__(self) -> str: ...

class X86_64_RELOCATION(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> X86_64_RELOCATION: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    UNSIGNED = 0

    SIGNED = 1

    BRANCH = 2

    GOT_LOAD = 3

    GOT = 4

    SUBTRACTOR = 5

    SIGNED_1 = 6

    SIGNED_2 = 7

    SIGNED_4 = 8

    TLV = 9

class X86_RELOCATION(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> X86_RELOCATION: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    VANILLA = 0

    PAIR = 1

    SECTDIFF = 2

    PB_LA_PTR = 3

    LOCAL_SECTDIFF = 4

    TLV = 5

@overload
def check_layout(file: Binary) -> tuple[bool, str]: ...

@overload
def check_layout(file: FatBinary) -> tuple[bool, str]: ...

def is_64(file: str) -> bool: ...

def is_fat(file: str) -> bool: ...

class it_data_in_code_entries:
    def __getitem__(self, arg: int, /) -> DataCodeEntry: ...

    def __len__(self) -> int: ...

    def __iter__(self) -> it_data_in_code_entries: ...

    def __next__(self) -> DataCodeEntry: ...

@overload
def parse(filename: str, config: ParserConfig = ...) -> Optional[FatBinary]: ...

@overload
def parse(raw: Sequence[int], config: ParserConfig = ...) -> Optional[FatBinary]: ...

@overload
def parse(obj: Union[io.IOBase | os.PathLike], config: ParserConfig = ...) -> Optional[FatBinary]: ...

def parse_from_memory(address: int, config: ParserConfig = ...) -> Optional[FatBinary]: ...
