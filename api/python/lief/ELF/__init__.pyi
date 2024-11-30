from collections.abc import Iterable, Mapping, Sequence
import enum
import io
import os
from typing import Iterator, Optional, Union, overload

import lief


class AArch64Feature(NoteGnuProperty.Property):
    @property
    def features(self) -> list[AArch64Feature.FEATURE]: ...

    class FEATURE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> AArch64Feature.FEATURE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        BTI = 1

        PAC = 2

class AArch64PAuth(NoteGnuProperty.Property):
    @property
    def platform(self) -> int: ...

    @property
    def version(self) -> int: ...

class ARCH(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> ARCH: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    NONE = 0

    M32 = 1

    SPARC = 2

    I386 = 3

    M68K = 4

    M88K = 5

    IAMCU = 6

    I860 = 7

    MIPS = 8

    S370 = 9

    MIPS_RS3_LE = 10

    PARISC = 15

    VPP500 = 17

    SPARC32PLUS = 18

    I60 = 19

    PPC = 20

    PPC64 = 21

    S390 = 22

    SPU = 23

    V800 = 36

    FR20 = 37

    RH32 = 38

    RCE = 39

    ARM = 40

    ALPHA = 41

    SH = 42

    SPARCV9 = 43

    TRICORE = 44

    ARC = 45

    H8_300 = 46

    H8_300H = 47

    H8S = 48

    H8_500 = 49

    IA_64 = 50

    MIPS_X = 51

    COLDFIRE = 52

    M68HC12 = 53

    MMA = 54

    PCP = 55

    NCPU = 56

    NDR1 = 57

    STARCORE = 58

    ME16 = 59

    ST100 = 60

    TINYJ = 61

    X86_64 = 62

    PDSP = 63

    PDP10 = 64

    PDP11 = 65

    FX66 = 66

    ST9PLUS = 67

    ST7 = 68

    M68HC16 = 69

    M68HC11 = 70

    M68HC08 = 71

    M68HC05 = 72

    SVX = 73

    ST19 = 74

    VAX = 75

    CRIS = 76

    JAVELIN = 77

    FIREPATH = 78

    ZSP = 79

    MMIX = 80

    HUANY = 81

    PRISM = 82

    AVR = 83

    FR30 = 84

    D10V = 85

    D30V = 86

    V850 = 87

    M32R = 88

    MN10300 = 89

    MN10200 = 90

    PJ = 91

    OPENRISC = 92

    ARC_COMPACT = 93

    XTENSA = 94

    VIDEOCORE = 95

    TMM_GPP = 96

    NS32K = 97

    TPC = 98

    SNP1K = 99

    ST200 = 100

    IP2K = 101

    MAX = 102

    CR = 103

    F2MC16 = 104

    MSP430 = 105

    BLACKFIN = 106

    SE_C33 = 107

    SEP = 108

    ARCA = 109

    UNICORE = 110

    EXCESS = 111

    DXP = 112

    ALTERA_NIOS2 = 113

    CRX = 114

    XGATE = 115

    C166 = 116

    M16C = 117

    DSPIC30F = 118

    CE = 119

    M32C = 120

    TSK3000 = 131

    RS08 = 132

    SHARC = 133

    ECOG2 = 134

    SCORE7 = 135

    DSP24 = 136

    VIDEOCORE3 = 137

    LATTICEMICO32 = 138

    SE_C17 = 139

    TI_C6000 = 140

    TI_C2000 = 141

    TI_C5500 = 142

    MMDSP_PLUS = 160

    CYPRESS_M8C = 161

    R32C = 162

    TRIMEDIA = 163

    HEXAGON = 164

    M8051 = 165

    STXP7X = 166

    NDS32 = 167

    ECOG1X = 168

    MAXQ30 = 169

    XIMO16 = 170

    MANIK = 171

    CRAYNV2 = 172

    RX = 173

    METAG = 174

    MCST_ELBRUS = 175

    ECOG16 = 176

    CR16 = 177

    ETPU = 178

    SLE9X = 179

    L10M = 180

    K10M = 181

    AARCH64 = 183

    AVR32 = 185

    STM8 = 186

    TILE64 = 187

    TILEPRO = 188

    CUDA = 190

    TILEGX = 191

    CLOUDSHIELD = 192

    COREA_1ST = 193

    COREA_2ND = 194

    ARC_COMPACT2 = 195

    OPEN8 = 196

    RL78 = 197

    VIDEOCORE5 = 198

    M78KOR = 199

    M56800EX = 200

    BA1 = 201

    BA2 = 202

    XCORE = 203

    MCHP_PIC = 204

    INTEL205 = 205

    INTEL206 = 206

    INTEL207 = 207

    INTEL208 = 208

    INTEL209 = 209

    KM32 = 210

    KMX32 = 211

    KMX16 = 212

    KMX8 = 213

    KVARC = 214

    CDP = 215

    COGE = 216

    COOL = 217

    NORC = 218

    CSR_KALIMBA = 219

    AMDGPU = 224

    RISCV = 243

    BPF = 247

    CSKY = 252

    LOONGARCH = 258

class AndroidIdent(Note):
    sdk_version: int

    ndk_version: str

    ndk_build_number: str

    def __str__(self) -> str: ...

class Binary(lief.Binary):
    class it_notes:
        def __getitem__(self, arg: int, /) -> Note: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_notes: ...

        def __next__(self) -> Note: ...

    class it_symbols_version_requirement:
        def __getitem__(self, arg: int, /) -> SymbolVersionRequirement: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_symbols_version_requirement: ...

        def __next__(self) -> SymbolVersionRequirement: ...

    class it_symbols_version_definition:
        def __getitem__(self, arg: int, /) -> SymbolVersionDefinition: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_symbols_version_definition: ...

        def __next__(self) -> SymbolVersionDefinition: ...

    class it_segments:
        def __getitem__(self, arg: int, /) -> Segment: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_segments: ...

        def __next__(self) -> Segment: ...

    class it_sections:
        def __getitem__(self, arg: int, /) -> Section: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_sections: ...

        def __next__(self) -> Section: ...

    class it_dynamic_entries:
        def __getitem__(self, arg: int, /) -> DynamicEntry: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_dynamic_entries: ...

        def __next__(self) -> DynamicEntry: ...

    class it_symbols_version:
        def __getitem__(self, arg: int, /) -> SymbolVersion: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_symbols_version: ...

        def __next__(self) -> SymbolVersion: ...

    class it_filter_relocation:
        def __getitem__(self, arg: int, /) -> Relocation: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_filter_relocation: ...

        def __next__(self) -> Relocation: ...

    class it_relocations:
        def __getitem__(self, arg: int, /) -> Relocation: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_relocations: ...

        def __next__(self) -> Relocation: ...

    class it_dyn_symtab_symbols:
        def __getitem__(self, arg: int, /) -> Symbol: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_dyn_symtab_symbols: ...

        def __next__(self) -> Symbol: ...

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

    class PHDR_RELOC(enum.Enum):
        AUTO = 0

        PIE_SHIFT = 1

        BSS_END = 2

        FILE_END = 3

        SEGMENT_GAP = 4

    @property
    def type(self) -> Header.CLASS: ...

    @property
    def header(self) -> Header: ... # type: ignore

    @property
    def sections(self) -> Binary.it_sections: ... # type: ignore

    @property
    def segments(self) -> Binary.it_segments: ...

    @property
    def dynamic_entries(self) -> Binary.it_dynamic_entries: ...

    @overload
    def add(self, arg: DynamicEntry, /) -> DynamicEntry: ...

    @overload
    def add(self, section: Section, loaded: bool = True) -> Section: ...

    @overload
    def add(self, segment: Segment, base: int = 0) -> Segment: ...

    @overload
    def add(self, note: Note) -> Note: ...

    @property
    def symtab_symbols(self) -> Binary.it_symbols: ...

    @property
    def dynamic_symbols(self) -> Binary.it_symbols: ...

    @property
    def symbols(self) -> Binary.it_dyn_symtab_symbols: ... # type: ignore

    @property
    def exported_symbols(self) -> Binary.it_filter_symbols: ...

    @property
    def imported_symbols(self) -> Binary.it_filter_symbols: ...

    @property
    def dynamic_relocations(self) -> Binary.it_filter_relocation: ...

    def add_dynamic_relocation(self, relocation: Relocation) -> Relocation: ...

    def add_pltgot_relocation(self, relocation: Relocation) -> Relocation: ...

    def add_object_relocation(self, relocation: Relocation, section: Section) -> Relocation: ...

    @property
    def pltgot_relocations(self) -> Binary.it_filter_relocation: ...

    @property
    def object_relocations(self) -> Binary.it_filter_relocation: ...

    @property
    def relocations(self) -> Binary.it_relocations: ... # type: ignore

    @property
    def symbols_version(self) -> Binary.it_symbols_version: ...

    @property
    def symbols_version_requirement(self) -> Binary.it_symbols_version_requirement: ...

    @property
    def symbols_version_definition(self) -> Binary.it_symbols_version_definition: ...

    @property
    def use_gnu_hash(self) -> bool: ...

    @property
    def gnu_hash(self) -> GnuHash: ...

    @property
    def use_sysv_hash(self) -> bool: ...

    @property
    def sysv_hash(self) -> SysvHash: ...

    @property
    def imagebase(self) -> int: ...

    @property
    def virtual_size(self) -> int: ...

    @property
    def is_pie(self) -> bool: ...

    @property
    def has_interpreter(self) -> bool: ...

    @property
    def functions(self) -> list[lief.Function]: ...

    interpreter: str

    def section_from_offset(self, offset: int, skip_nobits: bool = True) -> Section: ...

    def section_from_virtual_address(self, address: int, skip_nobits: bool = True) -> Section: ...

    def segment_from_virtual_address(self, address: int) -> Segment: ...

    def segment_from_offset(self, offset: int) -> Segment: ...

    @overload
    def get(self, tag: DynamicEntry.TAG) -> DynamicEntry: ...

    @overload
    def get(self, type: Segment.TYPE) -> Segment: ...

    @overload
    def get(self, type: Note.TYPE) -> Note: ...

    @overload
    def get(self, type: Section.TYPE) -> Section: ...

    @overload
    def has(self, tag: DynamicEntry.TAG) -> bool: ...

    @overload
    def has(self, type: Segment.TYPE) -> bool: ...

    @overload
    def has(self, type: Note.TYPE) -> bool: ...

    @overload
    def has(self, type: Section.TYPE) -> bool: ...

    @overload
    def patch_pltgot(self, symbol_name: str, address: int) -> None: ...

    @overload
    def patch_pltgot(self, symbol: Symbol, address: int) -> None: ...

    @overload
    def dynsym_idx(self, name: str) -> int: ...

    @overload
    def dynsym_idx(self, symbol: Symbol) -> int: ...

    @overload
    def symtab_idx(self, name: str) -> int: ...

    @overload
    def symtab_idx(self, symbol: Symbol) -> int: ...

    def has_section(self, section_name: str) -> bool: ...

    def has_section_with_offset(self, offset: int) -> bool: ...

    def has_section_with_va(self, virtual_address: int) -> bool: ...

    def get_section(self, section_name: str) -> Section: ...

    def add_symtab_symbol(self, symbol: Symbol) -> Symbol: ...

    def add_dynamic_symbol(self, symbol: Symbol, symbol_version: SymbolVersion | None = None) -> Symbol: ...

    def virtual_address_to_offset(self, virtual_address: int) -> Union[int, lief.lief_errors]: ...

    def replace(self, new_segment: Segment, original_segment: Segment, base: int = 0) -> Segment: ...

    @overload
    def extend(self, segment: Segment, size: int) -> Segment: ...

    @overload
    def extend(self, segment: Section, size: int) -> Section: ...

    @overload
    def remove(self, dynamic_entry: DynamicEntry) -> None: ...

    @overload
    def remove(self, tag: DynamicEntry.TAG) -> None: ...

    @overload
    def remove(self, section: Section, clear: bool = False) -> None: ...

    @overload
    def remove(self, note: Note) -> None: ...

    @overload
    def remove(self, type: Note.TYPE) -> None: ...

    @property
    def has_notes(self) -> bool: ...

    @property
    def notes(self) -> Binary.it_notes: ...

    def strip(self) -> None: ...

    def permute_dynamic_symbols(self, permutation: Sequence[int]) -> None: ...

    @overload
    def write(self, output: str) -> None: ...

    @overload
    def write(self, output: str, config: Builder.config_t) -> None: ...

    @property
    def last_offset_section(self) -> int: ...

    @property
    def last_offset_segment(self) -> int: ...

    @property
    def next_virtual_address(self) -> int: ...

    def add_library(self, library_name: str) -> DynamicEntryLibrary: ...

    def has_library(self, library_name: str) -> bool: ...

    def remove_library(self, library_name: str) -> None: ...

    def get_library(self, library_name: str) -> DynamicEntryLibrary: ...

    def has_dynamic_symbol(self, symbol_name: str) -> bool: ...

    def get_dynamic_symbol(self, symbol_name: str) -> Symbol: ...

    def has_symtab_symbol(self, symbol_name: str) -> bool: ...

    def get_symtab_symbol(self, symbol_name: str) -> Symbol: ...

    def get_strings(self, min_size: int = 5) -> list[str]: ...

    @property
    def strings(self) -> list[Union[str, bytes]]: ...

    def remove_symtab_symbol(self, arg: Symbol, /) -> None: ...

    @overload
    def remove_dynamic_symbol(self, arg: Symbol, /) -> None: ...

    @overload
    def remove_dynamic_symbol(self, arg: str, /) -> None: ...

    def add_exported_function(self, address: int, name: str = '') -> Symbol: ...

    @overload
    def export_symbol(self, symbol: Symbol) -> Symbol: ...

    @overload
    def export_symbol(self, symbol_name: str, value: int = 0) -> Symbol: ...

    @overload
    def get_relocation(self, symbol_name: str) -> Relocation: ...

    @overload
    def get_relocation(self, symbol: Symbol) -> Relocation: ...

    @overload
    def get_relocation(self, address: int) -> Relocation: ...

    @property
    def dtor_functions(self) -> list[lief.Function]: ...

    @property
    def eof_offset(self) -> int: ...

    @property
    def has_overlay(self) -> bool: ...

    @property
    def is_targeting_android(self) -> bool: ...

    overlay: memoryview

    def relocate_phdr_table(self, type: Binary.PHDR_RELOC = Binary.PHDR_RELOC.AUTO) -> int: ...

    def get_relocated_dynamic_array(self, array_tag: DynamicEntry.TAG) -> list[int]: ...

    @overload
    def __iadd__(self, arg: Segment, /) -> Binary: ...

    @overload
    def __iadd__(self, arg: Section, /) -> Binary: ...

    @overload
    def __iadd__(self, arg: DynamicEntry, /) -> Binary: ...

    @overload
    def __iadd__(self, arg: Note, /) -> Binary: ...

    @overload
    def __isub__(self, arg: DynamicEntry, /) -> Binary: ...

    @overload
    def __isub__(self, arg: DynamicEntry.TAG, /) -> Binary: ...

    @overload
    def __isub__(self, arg: Note, /) -> Binary: ...

    @overload
    def __isub__(self, arg: Note.TYPE, /) -> Binary: ...

    @overload
    def __getitem__(self, arg: Segment.TYPE, /) -> Segment: ...

    @overload
    def __getitem__(self, arg: Note.TYPE, /) -> Note: ...

    @overload
    def __getitem__(self, arg: DynamicEntry.TAG, /) -> DynamicEntry: ...

    @overload
    def __getitem__(self, arg: Section.TYPE, /) -> Section: ...

    @overload
    def __contains__(self, arg: Segment.TYPE, /) -> bool: ...

    @overload
    def __contains__(self, arg: DynamicEntry.TAG, /) -> bool: ...

    @overload
    def __contains__(self, arg: Note.TYPE, /) -> bool: ...

    @overload
    def __contains__(self, arg: Section.TYPE, /) -> bool: ...

    def __str__(self) -> str: ...

class Builder:
    def __init__(self, elf_binary: Binary) -> None: ...

    class config_t:
        def __init__(self) -> None: ...

        force_relocate: bool

        dt_hash: bool

        dyn_str: bool

        dynamic_section: bool

        fini_array: bool

        init_array: bool

        interpreter: bool

        jmprel: bool

        notes: bool

        preinit_array: bool

        relr: bool

        android_rela: bool

        rela: bool

        static_symtab: bool

        sym_verdef: bool

        sym_verneed: bool

        sym_versym: bool

        symtab: bool

        coredump_notes: bool

    def build(self) -> None: ...

    config: lief.ELF.Builder.config_t

    def write(self, output: str) -> None: ...

    def get_build(self) -> list[int]: ...

class CoreAuxv(Note):
    class TYPE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> CoreAuxv.TYPE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        END = 0

        IGNORE = 1

        EXECFD = 2

        PHDR = 3

        PHENT = 4

        PHNUM = 5

        PAGESZ = 6

        BASE = 7

        FLAGS = 8

        ENTRY = 9

        NOTELF = 10

        UID = 11

        EUID = 12

        GID = 13

        EGID = 14

        TGT_PLATFORM = 15

        HWCAP = 16

        CLKTCK = 17

        FPUCW = 18

        DCACHEBSIZE = 19

        ICACHEBSIZE = 20

        UCACHEBSIZE = 21

        IGNOREPPC = 22

        SECURE = 23

        BASE_PLATFORM = 24

        RANDOM = 25

        HWCAP2 = 26

        EXECFN = 31

        SYSINFO = 32

        SYSINFO_EHDR = 33

    @property
    def values(self) -> dict[CoreAuxv.TYPE, int]: ...

    def get(self, type: CoreAuxv.TYPE) -> Optional[int]: ...

    def __getitem__(self, arg: CoreAuxv.TYPE, /) -> Optional[int]: ...

    @overload
    def set(self, type: CoreAuxv.TYPE, value: int) -> bool: ...

    @overload
    def set(self, arg: Mapping[CoreAuxv.TYPE, int], /) -> bool: ...

    @overload
    def __setitem__(self, arg0: CoreAuxv.TYPE, arg1: int, /) -> bool: ...

    @overload
    def __setitem__(self, arg: Mapping[CoreAuxv.TYPE, int], /) -> bool: ...

    def __str__(self) -> str: ...

class CoreFile(Note):
    class files_t:
        @overload
        def __init__(self) -> None: ...

        @overload
        def __init__(self, arg: CoreFile.files_t) -> None: ...

        @overload
        def __init__(self, arg: Iterable[CoreFile.entry_t], /) -> None: ...

        def __len__(self) -> int: ...

        def __bool__(self) -> bool: ...

        def __repr__(self) -> str: ...

        def __iter__(self) -> Iterator[CoreFile.entry_t]: ...

        @overload
        def __getitem__(self, arg: int, /) -> CoreFile.entry_t: ...

        @overload
        def __getitem__(self, arg: slice, /) -> CoreFile.files_t: ...

        def clear(self) -> None: ...

        def append(self, arg: CoreFile.entry_t, /) -> None: ...

        def insert(self, arg0: int, arg1: CoreFile.entry_t, /) -> None: ...

        def pop(self, index: int = -1) -> CoreFile.entry_t: ...

        def extend(self, arg: CoreFile.files_t, /) -> None: ...

        @overload
        def __setitem__(self, arg0: int, arg1: CoreFile.entry_t, /) -> None: ...

        @overload
        def __setitem__(self, arg0: slice, arg1: CoreFile.files_t, /) -> None: ...

        @overload
        def __delitem__(self, arg: int, /) -> None: ...

        @overload
        def __delitem__(self, arg: slice, /) -> None: ...

    class entry_t:
        start: int

        end: int

        file_ofs: int

        path: str

        def __str__(self) -> str: ...

    files: lief.ELF.CoreFile.files_t

    def __len__(self) -> int: ...

    def __iter__(self) -> Iterator[CoreFile.entry_t]: ...

    def __str__(self) -> str: ...

class CorePrPsInfo(Note):
    class info_t:
        state: int

        sname: str

        zombie: bool

        nice: int

        flag: int

        uid: int

        gid: int

        pid: int

        ppid: int

        pgrp: int

        sid: int

        filename: str

        args: str

        @property
        def filename_stripped(self) -> str: ...

        @property
        def args_stripped(self) -> str: ...

    info: Optional[lief.ELF.CorePrPsInfo.info_t]

    def __str__(self) -> str: ...

class CorePrStatus(Note):
    class timeval_t:
        sec: int

        usec: int

    class siginfo_t:
        sicode: int

        errno: int

        signo: int

    class pr_status_t:
        info: lief.ELF.CorePrStatus.siginfo_t

        cursig: int

        reserved: int

        sigpend: int

        sighold: int

        pid: int

        ppid: int

        pgrp: int

        sid: int

        utime: lief.ELF.CorePrStatus.timeval_t

        stime: lief.ELF.CorePrStatus.timeval_t

        cutime: lief.ELF.CorePrStatus.timeval_t

        cstime: lief.ELF.CorePrStatus.timeval_t

    class Registers:
        class X86(enum.Enum):
            @staticmethod
            def from_value(arg: int, /) -> CorePrStatus.Registers.X86: ...

            def __eq__(self, arg, /) -> bool: ...

            def __ne__(self, arg, /) -> bool: ...

            def __int__(self) -> int: ...

            EBX = 0

            ECX = 1

            EDX = 2

            ESI = 3

            EDI = 4

            EBP = 5

            EAX = 6

            DS = 7

            ES = 8

            FS = 9

            GS = 10

            ORIG_EAX = 11

            EIP = 12

            CS = 13

            EFLAGS = 14

            ESP = 15

            SS = 16

        class X86_64(enum.Enum):
            @staticmethod
            def from_value(arg: int, /) -> CorePrStatus.Registers.X86_64: ...

            def __eq__(self, arg, /) -> bool: ...

            def __ne__(self, arg, /) -> bool: ...

            def __int__(self) -> int: ...

            R15 = 0

            R14 = 1

            R13 = 2

            R12 = 3

            RBP = 4

            RBX = 5

            R11 = 6

            R10 = 7

            R9 = 8

            R8 = 9

            RAX = 10

            RCX = 11

            RDX = 12

            RSI = 13

            RDI = 14

            ORIG_RAX = 15

            RIP = 16

            CS = 17

            EFLAGS = 18

            RSP = 19

            SS = 20

        class ARM(enum.Enum):
            @staticmethod
            def from_value(arg: int, /) -> CorePrStatus.Registers.ARM: ...

            def __eq__(self, arg, /) -> bool: ...

            def __ne__(self, arg, /) -> bool: ...

            def __int__(self) -> int: ...

            R0 = 0

            R1 = 1

            R2 = 2

            R3 = 3

            R4 = 4

            R5 = 5

            R6 = 6

            R7 = 7

            R8 = 8

            R9 = 9

            R10 = 10

            R11 = 11

            R12 = 12

            R13 = 13

            R14 = 14

            R15 = 15

            CPSR = 16

        class AARCH64(enum.Enum):
            @staticmethod
            def from_value(arg: int, /) -> CorePrStatus.Registers.AARCH64: ...

            def __eq__(self, arg, /) -> bool: ...

            def __ne__(self, arg, /) -> bool: ...

            def __int__(self) -> int: ...

            X0 = 0

            X1 = 1

            X2 = 2

            X3 = 3

            X4 = 4

            X5 = 5

            X6 = 6

            X7 = 7

            X8 = 8

            X9 = 9

            X10 = 10

            X11 = 11

            X12 = 12

            X13 = 13

            X14 = 14

            X15 = 15

            X16 = 16

            X17 = 17

            X18 = 18

            X19 = 19

            X20 = 20

            X21 = 21

            X22 = 22

            X23 = 23

            X24 = 24

            X25 = 25

            X26 = 26

            X27 = 27

            X28 = 28

            X29 = 29

            X30 = 30

            X31 = 31

            PC = 32

            PSTATE = 33

    status: lief.ELF.CorePrStatus.pr_status_t

    @property
    def architecture(self) -> ARCH: ...

    @property
    def pc(self) -> Optional[int]: ...

    @property
    def sp(self) -> Optional[int]: ...

    @property
    def return_value(self) -> Optional[int]: ...

    @property
    def register_values(self) -> list[int]: ...

    @overload
    def get(self, reg: CorePrStatus.Registers.X86) -> Optional[int]: ...

    @overload
    def get(self, reg: CorePrStatus.Registers.X86_64) -> Optional[int]: ...

    @overload
    def get(self, reg: CorePrStatus.Registers.ARM) -> Optional[int]: ...

    @overload
    def get(self, reg: CorePrStatus.Registers.AARCH64) -> Optional[int]: ...

    @overload
    def __getitem__(self, arg: CorePrStatus.Registers.X86, /) -> Optional[int]: ...

    @overload
    def __getitem__(self, arg: CorePrStatus.Registers.X86_64, /) -> Optional[int]: ...

    @overload
    def __getitem__(self, arg: CorePrStatus.Registers.ARM, /) -> Optional[int]: ...

    @overload
    def __getitem__(self, arg: CorePrStatus.Registers.AARCH64, /) -> Optional[int]: ...

    @overload
    def set(self, reg: CorePrStatus.Registers.X86, value: int) -> lief.ok_error_t: ...

    @overload
    def set(self, reg: CorePrStatus.Registers.X86_64, value: int) -> lief.ok_error_t: ...

    @overload
    def set(self, reg: CorePrStatus.Registers.ARM, value: int) -> lief.ok_error_t: ...

    @overload
    def set(self, reg: CorePrStatus.Registers.AARCH64, value: int) -> lief.ok_error_t: ...

    @overload
    def __setitem__(self, arg0: CorePrStatus.Registers.X86, arg1: int, /) -> lief.ok_error_t: ...

    @overload
    def __setitem__(self, arg0: CorePrStatus.Registers.X86_64, arg1: int, /) -> lief.ok_error_t: ...

    @overload
    def __setitem__(self, arg0: CorePrStatus.Registers.ARM, arg1: int, /) -> lief.ok_error_t: ...

    @overload
    def __setitem__(self, arg0: CorePrStatus.Registers.AARCH64, arg1: int, /) -> lief.ok_error_t: ...

    def __str__(self) -> str: ...

class CoreSigInfo(Note):
    signo: Optional[int]

    sigcode: Optional[int]

    sigerrno: Optional[int]

    def __str__(self) -> str: ...

class DynamicEntry(lief.Object):
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, tag: DynamicEntry.TAG, value: int) -> None: ...

    class TAG(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> DynamicEntry.TAG: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 18446744073709551615

        NULL = 0

        NEEDED = 1

        PLTRELSZ = 2

        PLTGOT = 3

        HASH = 4

        STRTAB = 5

        SYMTAB = 6

        RELA = 7

        RELASZ = 8

        RELAENT = 9

        STRSZ = 10

        SYMENT = 11

        INIT = 12

        FINI = 13

        SONAME = 14

        RPATH = 15

        SYMBOLIC = 16

        REL = 17

        RELSZ = 18

        RELENT = 19

        PLTREL = 20

        DEBUG_TAG = 21

        TEXTREL = 22

        JMPREL = 23

        BIND_NOW = 24

        INIT_ARRAY = 25

        FINI_ARRAY = 26

        INIT_ARRAYSZ = 27

        FINI_ARRAYSZ = 28

        RUNPATH = 29

        FLAGS = 30

        PREINIT_ARRAY = 32

        PREINIT_ARRAYSZ = 33

        SYMTAB_SHNDX = 34

        RELRSZ = 35

        RELR = 36

        RELRENT = 37

        GNU_HASH = 1879047925

        RELACOUNT = 1879048185

        RELCOUNT = 1879048186

        FLAGS_1 = 1879048187

        VERSYM = 1879048176

        VERDEF = 1879048188

        VERDEFNUM = 1879048189

        VERNEED = 1879048190

        VERNEEDNUM = 1879048191

        ANDROID_REL_OFFSET = 1610612749

        ANDROID_REL_SIZE = 1610612750

        ANDROID_REL = 1610612751

        ANDROID_RELSZ = 1610612752

        ANDROID_RELA = 1610612753

        ANDROID_RELASZ = 1610612754

        ANDROID_RELR = 1879040000

        ANDROID_RELRSZ = 1879040001

        ANDROID_RELRENT = 1879040003

        ANDROID_RELRCOUNT = 1879040005

        MIPS_RLD_VERSION = 6174015489

        MIPS_TIME_STAMP = 6174015490

        MIPS_ICHECKSUM = 6174015491

        MIPS_IVERSION = 6174015492

        MIPS_FLAGS = 6174015493

        MIPS_BASE_ADDRESS = 6174015494

        MIPS_MSYM = 6174015495

        MIPS_CONFLICT = 6174015496

        MIPS_LIBLIST = 6174015497

        MIPS_LOCAL_GOTNO = 6174015498

        MIPS_CONFLICTNO = 6174015499

        MIPS_LIBLISTNO = 6174015504

        MIPS_SYMTABNO = 6174015505

        MIPS_UNREFEXTNO = 6174015506

        MIPS_GOTSYM = 6174015507

        MIPS_HIPAGENO = 6174015508

        MIPS_RLD_MAP = 6174015510

        MIPS_DELTA_CLASS = 6174015511

        MIPS_DELTA_CLASS_NO = 6174015512

        MIPS_DELTA_INSTANCE = 6174015513

        MIPS_DELTA_INSTANCE_NO = 6174015514

        MIPS_DELTA_RELOC = 6174015515

        MIPS_DELTA_RELOC_NO = 6174015516

        MIPS_DELTA_SYM = 6174015517

        MIPS_DELTA_SYM_NO = 6174015518

        MIPS_DELTA_CLASSSYM = 6174015520

        MIPS_DELTA_CLASSSYM_NO = 6174015521

        MIPS_CXX_FLAGS = 6174015522

        MIPS_PIXIE_INIT = 6174015523

        MIPS_SYMBOL_LIB = 6174015524

        MIPS_LOCALPAGE_GOTIDX = 6174015525

        MIPS_LOCAL_GOTIDX = 6174015526

        MIPS_HIDDEN_GOTIDX = 6174015527

        MIPS_PROTECTED_GOTIDX = 6174015528

        MIPS_OPTIONS = 6174015529

        MIPS_INTERFACE = 6174015530

        MIPS_DYNSTR_ALIGN = 6174015531

        MIPS_INTERFACE_SIZE = 6174015532

        MIPS_RLD_TEXT_RESOLVE_ADDR = 6174015533

        MIPS_PERF_SUFFIX = 6174015534

        MIPS_COMPACT_SIZE = 6174015535

        MIPS_GP_VALUE = 6174015536

        MIPS_AUX_DYNAMIC = 6174015537

        MIPS_PLTGOT = 6174015538

        MIPS_RWPLT = 6174015540

        MIPS_RLD_MAP_REL = 6174015541

        MIPS_XHASH = 6174015542

        AARCH64_BTI_PLT = 10468982785

        AARCH64_PAC_PLT = 10468982787

        AARCH64_VARIANT_PCS = 10468982789

        AARCH64_MEMTAG_MODE = 10468982793

        AARCH64_MEMTAG_HEAP = 10468982795

        AARCH64_MEMTAG_STACK = 10468982796

        AARCH64_MEMTAG_GLOBALS = 10468982797

        AARCH64_MEMTAG_GLOBALSSZ = 10468982799

        HEXAGON_SYMSZ = 14763950080

        HEXAGON_VER = 14763950081

        HEXAGON_PLT = 14763950082

        PPC_GOT = 19058917376

        PPC_OPT = 19058917377

        PPC64_GLINK = 23353884672

        PPC64_OPT = 23353884675

        RISCV_VARIANT_CC = 27648851971

        X86_64_PLT = 31943819264

        X86_64_PLTSZ = 31943819265

        X86_64_PLTENT = 31943819267

    tag: lief.ELF.DynamicEntry.TAG

    value: int

    def __str__(self) -> str: ...

class DynamicEntryArray(DynamicEntry):
    def __init__(self, tag: DynamicEntry.TAG, array: Sequence[int]) -> None: ...

    array: list[int]

    def insert(self, pos: int, function: int) -> DynamicEntryArray: ...

    def append(self, function: int) -> DynamicEntryArray: ...

    def remove(self, function: int) -> DynamicEntryArray: ...

    def __iadd__(self, arg: int, /) -> DynamicEntryArray: ...

    def __isub__(self, arg: int, /) -> DynamicEntryArray: ...

    def __getitem__(self, arg: int, /) -> int: ...

    def __len__(self) -> int: ...

    def __str__(self) -> str: ...

class DynamicEntryFlags(DynamicEntry):
    class FLAG(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> DynamicEntryFlags.FLAG: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        ORIGIN = 1

        SYMBOLIC = 2

        TEXTREL = 4

        BIND_NOW = 8

        STATIC_TLS = 16

        NOW = 4294967297

        GLOBAL = 4294967298

        GROUP = 4294967300

        NODELETE = 4294967304

        LOADFLTR = 4294967312

        INITFIRST = 4294967328

        NOOPEN = 4294967360

        HANDLE_ORIGIN = 4294967424

        DIRECT = 4294967552

        TRANS = 4294967808

        INTERPOSE = 4294968320

        NODEFLIB = 4294969344

        NODUMP = 4294971392

        CONFALT = 4294975488

        ENDFILTEE = 4294983680

        DISPRELDNE = 4295000064

        DISPRELPND = 4295032832

        NODIRECT = 4295098368

        IGNMULDEF = 4295229440

        NOKSYMS = 4295491584

        NOHDR = 4296015872

        EDITED = 4297064448

        NORELOC = 4299161600

        SYMINTPOSE = 4303355904

        GLOBAUDIT = 4311744512

        SINGLETON = 4328521728

        PIE = 4429185024

        KMOD = 4563402752

        WEAKFILTER = 4831838208

        NOCOMMON = 5368709120

    @property
    def flags(self) -> list[DynamicEntryFlags.FLAG]: ...

    def has(self, flag: DynamicEntryFlags.FLAG) -> bool: ...

    def add(self, flag: DynamicEntryFlags.FLAG) -> None: ...

    def remove(self, flag: DynamicEntryFlags.FLAG) -> None: ...

    def __iadd__(self, arg: DynamicEntryFlags.FLAG, /) -> DynamicEntryFlags: ...

    def __isub__(self, arg: DynamicEntryFlags.FLAG, /) -> DynamicEntryFlags: ...

    def __contains__(self, arg: DynamicEntryFlags.FLAG, /) -> bool: ...

    def __str__(self) -> str: ...

class DynamicEntryLibrary(DynamicEntry):
    def __init__(self, library_name: str) -> None: ...

    name: Union[str, bytes]

    def __str__(self) -> str: ...

class DynamicEntryRpath(DynamicEntry):
    @overload
    def __init__(self, path: str = '') -> None: ...

    @overload
    def __init__(self, paths: Sequence[str]) -> None: ...

    rpath: Union[str, bytes]

    paths: list[str]

    def insert(self, position: int, path: str) -> DynamicEntryRpath: ...

    def append(self, path: str) -> DynamicEntryRpath: ...

    def remove(self, path: str) -> DynamicEntryRpath: ...

    def __iadd__(self, arg: str, /) -> DynamicEntryRpath: ...

    def __isub__(self, arg: str, /) -> DynamicEntryRpath: ...

    def __str__(self) -> str: ...

class DynamicEntryRunPath(DynamicEntry):
    @overload
    def __init__(self, path: str = '') -> None: ...

    @overload
    def __init__(self, paths: Sequence[str]) -> None: ...

    runpath: Union[str, bytes]

    paths: list[str]

    def insert(self, position: int, path: str) -> DynamicEntryRunPath: ...

    def append(self, path: str) -> DynamicEntryRunPath: ...

    def remove(self, path: str) -> DynamicEntryRunPath: ...

    def __iadd__(self, arg: str, /) -> DynamicEntryRunPath: ...

    def __isub__(self, arg: str, /) -> DynamicEntryRunPath: ...

    def __str__(self) -> str: ...

class DynamicSharedObject(DynamicEntry):
    def __init__(self, library_name: str) -> None: ...

    name: Union[str, bytes]

    def __str__(self) -> str: ...

class Generic(NoteGnuProperty.Property):
    @property
    def raw_type(self) -> int: ...

class GnuHash(lief.Object):
    def __init__(self) -> None: ...

    @property
    def nb_buckets(self) -> int: ...

    @property
    def symbol_index(self) -> int: ...

    @property
    def shift2(self) -> int: ...

    @property
    def bloom_filters(self) -> list[int]: ...

    @property
    def buckets(self) -> list[int]: ...

    @property
    def hash_values(self) -> list[int]: ...

    def check_bloom_filter(self, hash: int) -> bool: ...

    def check_bucket(self, hash: int) -> bool: ...

    @overload
    def check(self, symbol_name: str) -> bool: ...

    @overload
    def check(self, hash_value: int) -> bool: ...

    def __str__(self) -> str: ...

class Header(lief.Object):
    def __init__(self) -> None: ...

    class FILE_TYPE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Header.FILE_TYPE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        NONE = 0

        REL = 1

        EXEC = 2

        DYN = 3

        CORE = 4

    class VERSION(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Header.VERSION: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        NONE = 0

        CURRENT = 1

    class CLASS(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Header.CLASS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        NONE = 0

        ELF32 = 1

        ELF64 = 2

    class OS_ABI(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Header.OS_ABI: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        SYSTEMV = 0

        HPUX = 1

        NETBSD = 2

        LINUX = 3

        HURD = 4

        SOLARIS = 6

        AIX = 7

        IRIX = 8

        FREEBSD = 9

        TRU64 = 10

        MODESTO = 11

        OPENBSD = 12

        OPENVMS = 13

        NSK = 14

        AROS = 15

        FENIXOS = 16

        CLOUDABI = 17

        AMDGPU_HSA = 64

        C6000_LINUX = 65

        ARM = 97

        STANDALONE = 255

    class ELF_DATA(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Header.ELF_DATA: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        NONE = 0

        LSB = 1

        MSB = 2

    identity_class: lief.ELF.Header.CLASS

    identity_data: lief.ELF.Header.ELF_DATA

    identity_version: lief.ELF.Header.VERSION

    identity_os_abi: lief.ELF.Header.OS_ABI

    identity_abi_version: int

    identity: list[int]

    file_type: lief.ELF.Header.FILE_TYPE

    machine_type: lief.ELF.ARCH

    object_file_version: lief.ELF.Header.VERSION

    entrypoint: int

    program_header_offset: int

    section_header_offset: int

    processor_flag: int

    def has(self, arg: PROCESSOR_FLAGS, /) -> bool: ...

    @property
    def flags_list(self) -> list[PROCESSOR_FLAGS]: ...

    header_size: int

    program_header_size: int

    numberof_segments: int

    section_header_size: int

    numberof_sections: int

    section_name_table_idx: int

    def __str__(self) -> str: ...

class Note(lief.Object):
    class TYPE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Note.TYPE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        GNU_ABI_TAG = 1

        GNU_HWCAP = 2

        GNU_BUILD_ID = 3

        GNU_GOLD_VERSION = 4

        GNU_PROPERTY_TYPE_0 = 5

        GNU_BUILD_ATTRIBUTE_OPEN = 6

        GNU_BUILD_ATTRIBUTE_FUNC = 7

        CRASHPAD = 8

        CORE_PRSTATUS = 9

        CORE_FPREGSET = 10

        CORE_PRPSINFO = 11

        CORE_TASKSTRUCT = 12

        CORE_AUXV = 13

        CORE_PSTATUS = 14

        CORE_FPREGS = 15

        CORE_PSINFO = 16

        CORE_LWPSTATUS = 17

        CORE_LWPSINFO = 18

        CORE_WIN32PSTATUS = 19

        CORE_FILE = 20

        CORE_PRXFPREG = 21

        CORE_SIGINFO = 22

        CORE_ARM_VFP = 23

        CORE_ARM_TLS = 24

        CORE_ARM_HW_BREAK = 25

        CORE_ARM_HW_WATCH = 26

        CORE_ARM_SYSTEM_CALL = 27

        CORE_ARM_SVE = 28

        CORE_ARM_PAC_MASK = 29

        CORE_ARM_PACA_KEYS = 30

        CORE_ARM_PACG_KEYS = 31

        CORE_TAGGED_ADDR_CTRL = 32

        CORE_PAC_ENABLED_KEYS = 33

        CORE_X86_TLS = 34

        CORE_X86_IOPERM = 35

        CORE_X86_XSTATE = 36

        CORE_X86_CET = 37

        ANDROID_MEMTAG = 39

        ANDROID_KUSER = 40

        ANDROID_IDENT = 38

        GO_BUILDID = 41

        STAPSDT = 42

        QNX_STACK = 43

    @overload
    @staticmethod
    def create(name: str, original_type: int, description: Sequence[int], section_name: str, file_type: Header.FILE_TYPE = Header.FILE_TYPE.NONE, arch: ARCH = ARCH.NONE, cls: Header.CLASS = Header.CLASS.NONE) -> Optional[Note]: ...

    @overload
    @staticmethod
    def create(raw: bytes, section_name: str = '', file_type: Header.FILE_TYPE = Header.FILE_TYPE.NONE, arch: ARCH = ARCH.NONE, cls: Header.CLASS = Header.CLASS.NONE) -> Optional[Note]: ...

    @overload
    @staticmethod
    def create(name: str, type: Note.TYPE, description: Sequence[int], section_name: str, arch: ARCH = ARCH.NONE, cls: Header.CLASS = Header.CLASS.NONE) -> Optional[Note]: ...

    name: str

    @property
    def original_type(self) -> int: ...

    @property
    def type(self) -> Note.TYPE: ...

    description: memoryview

    @property
    def size(self) -> int: ...

    def copy(self) -> Optional[Note]: ...

    def __str__(self) -> str: ...

class NoteAbi(Note):
    class ABI(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> NoteAbi.ABI: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        LINUX = 0

        GNU = 1

        SOLARIS2 = 2

        FREEBSD = 3

        NETBSD = 4

        SYLLABLE = 5

        NACL = 6

    @property
    def abi(self) -> Optional[NoteAbi.ABI]: ...

    @property
    def version(self) -> Optional[list[int]]: ...

    def __str__(self) -> str: ...

class NoteGnuProperty(Note):
    class Property:
        @property
        def type(self) -> NoteGnuProperty.Property.TYPE: ...

        def __str__(self) -> str: ...

        class TYPE(enum.Enum):
            @staticmethod
            def from_value(arg: int, /) -> NoteGnuProperty.Property.TYPE: ...

            def __eq__(self, arg, /) -> bool: ...

            def __ne__(self, arg, /) -> bool: ...

            def __int__(self) -> int: ...

            UNKNOWN = 0

            GENERIC = 1

            AARCH64_FEATURES = 2

            AARCH64_PAUTH = 3

            STACK_SIZE = 4

            NO_COPY_ON_PROTECTED = 5

            X86_ISA = 6

            X86_FEATURE = 7

            NEEDED = 8

    @property
    def properties(self) -> list[Optional[NoteGnuProperty.Property]]: ...

    def find(self, arg: NoteGnuProperty.Property.TYPE, /) -> Optional[NoteGnuProperty.Property]: ...

    def __str__(self) -> str: ...

class NoteNoCopyOnProtected(NoteGnuProperty.Property):
    pass

class PROCESSOR_FLAGS(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> PROCESSOR_FLAGS: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    ARM_EABI_UNKNOWN = 8796093022208

    ARM_SOFT_FLOAT = 8796093022720

    ARM_VFP_FLOAT = 8796093023232

    ARM_EABI_VER1 = 8796109799424

    ARM_EABI_VER2 = 8796126576640

    ARM_EABI_VER3 = 8796143353856

    ARM_EABI_VER4 = 8796160131072

    ARM_EABI_VER5 = 8796176908288

    HEXAGON_MACH_V2 = 17592186044417

    HEXAGON_MACH_V3 = 17592186044418

    HEXAGON_MACH_V4 = 17592186044419

    HEXAGON_MACH_V5 = 17592186044420

    HEXAGON_ISA_V2 = 17592186044432

    HEXAGON_ISA_V3 = 17592186044448

    HEXAGON_ISA_V4 = 17592186044464

    HEXAGON_ISA_V5 = 17592186044480

    LOONGARCH_ABI_SOFT_FLOAT = 26388279066625

    LOONGARCH_ABI_SINGLE_FLOAT = 26388279066626

    LOONGARCH_ABI_DOUBLE_FLOAT = 26388279066627

    MIPS_NOREORDER = 35184372088833

    MIPS_PIC = 35184372088834

    MIPS_CPIC = 35184372088836

    MIPS_ABI2 = 35184372088864

    MIPS_32BITMODE = 35184372089088

    MIPS_FP64 = 35184372089344

    MIPS_NAN2008 = 35184372089856

    MIPS_ABI_O32 = 35184372092928

    MIPS_ABI_O64 = 35184372097024

    MIPS_ABI_EABI32 = 35184372101120

    MIPS_ABI_EABI64 = 35184372105216

    MIPS_MACH_3900 = 35184380542976

    MIPS_MACH_4010 = 35184380608512

    MIPS_MACH_4100 = 35184380674048

    MIPS_MACH_4650 = 35184380805120

    MIPS_MACH_4120 = 35184380936192

    MIPS_MACH_4111 = 35184381001728

    MIPS_MACH_SB1 = 35184381132800

    MIPS_MACH_OCTEON = 35184381198336

    MIPS_MACH_XLR = 35184381263872

    MIPS_MACH_OCTEON2 = 35184381329408

    MIPS_MACH_OCTEON3 = 35184381394944

    MIPS_MACH_5400 = 35184381591552

    MIPS_MACH_5900 = 35184381657088

    MIPS_MACH_5500 = 35184382050304

    MIPS_MACH_9000 = 35184382115840

    MIPS_MACH_LS2E = 35184382574592

    MIPS_MACH_LS2F = 35184382640128

    MIPS_MACH_LS3A = 35184382705664

    MIPS_MICROMIPS = 35184405643264

    MIPS_ARCH_ASE_M16 = 35184439197696

    MIPS_ARCH_ASE_MDMX = 35184506306560

    MIPS_ARCH_1 = 35184372088832

    MIPS_ARCH_2 = 35184640524288

    MIPS_ARCH_3 = 35184908959744

    MIPS_ARCH_4 = 35185177395200

    MIPS_ARCH_5 = 35185445830656

    MIPS_ARCH_32 = 35185714266112

    MIPS_ARCH_64 = 35185982701568

    MIPS_ARCH_32R2 = 35186251137024

    MIPS_ARCH_64R2 = 35186519572480

    MIPS_ARCH_32R6 = 35186788007936

    MIPS_ARCH_64R6 = 35187056443392

    RISCV_RVC = 43980465111041

    RISCV_FLOAT_ABI_SOFT = 43980465111040

    RISCV_FLOAT_ABI_SINGLE = 43980465111042

    RISCV_FLOAT_ABI_DOUBLE = 43980465111044

    RISCV_FLOAT_ABI_QUAD = 43980465111046

    RISCV_FLOAT_ABI_RVE = 43980465111048

    RISCV_FLOAT_ABI_TSO = 43980465111056

class ParserConfig:
    def __init__(self) -> None: ...

    class DYNSYM_COUNT(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> ParserConfig.DYNSYM_COUNT: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        AUTO = 0

        SECTION = 1

        HASH = 2

        RELOCATIONS = 3

    parse_relocations: bool

    parse_dyn_symbols: bool

    parse_symtab_symbols: bool

    parse_symbol_versions: bool

    parse_notes: bool

    parse_overlay: bool

    count_mtd: lief.ELF.ParserConfig.DYNSYM_COUNT

    all: lief.ELF.ParserConfig = ...

class QNXStack(Note):
    stack_size: int

    stack_allocated: int

    is_executable: bool

    def __str__(self) -> str: ...

class Relocation(lief.Relocation):
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, arch: ARCH) -> None: ...

    @overload
    def __init__(self, address: int, type: Relocation.TYPE, encoding: Relocation.ENCODING) -> None: ...

    class TYPE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Relocation.TYPE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        X86_64_NONE = 134217728

        X86_64_64 = 134217729

        X86_64_PC32 = 134217730

        X86_64_GOT32 = 134217731

        X86_64_PLT32 = 134217732

        X86_64_COPY = 134217733

        X86_64_GLOB_DAT = 134217734

        X86_64_JUMP_SLOT = 134217735

        X86_64_RELATIVE = 134217736

        X86_64_GOTPCREL = 134217737

        X86_64_32 = 134217738

        X86_64_32S = 134217739

        X86_64_16 = 134217740

        X86_64_PC16 = 134217741

        X86_64_8 = 134217742

        X86_64_PC8 = 134217743

        X86_64_DTPMOD64 = 134217744

        X86_64_DTPOFF64 = 134217745

        X86_64_TPOFF64 = 134217746

        X86_64_TLSGD = 134217747

        X86_64_TLSLD = 134217748

        X86_64_DTPOFF32 = 134217749

        X86_64_GOTTPOFF = 134217750

        X86_64_TPOFF32 = 134217751

        X86_64_PC64 = 134217752

        X86_64_GOTOFF64 = 134217753

        X86_64_GOTPC32 = 134217754

        X86_64_GOT64 = 134217755

        X86_64_GOTPCREL64 = 134217756

        X86_64_GOTPC64 = 134217757

        X86_64_GOTPLT64 = 134217758

        X86_64_PLTOFF64 = 134217759

        X86_64_SIZE32 = 134217760

        X86_64_SIZE64 = 134217761

        X86_64_GOTPC32_TLSDESC = 134217762

        X86_64_TLSDESC_CALL = 134217763

        X86_64_TLSDESC = 134217764

        X86_64_IRELATIVE = 134217765

        X86_64_RELATIVE64 = 134217766

        X86_64_PC32_BND = 134217767

        X86_64_PLT32_BND = 134217768

        X86_64_GOTPCRELX = 134217769

        X86_64_REX_GOTPCRELX = 134217770

        AARCH64_NONE = 268435456

        AARCH64_ABS64 = 268435713

        AARCH64_ABS32 = 268435714

        AARCH64_ABS16 = 268435715

        AARCH64_PREL64 = 268435716

        AARCH64_PREL32 = 268435717

        AARCH64_PREL16 = 268435718

        AARCH64_MOVW_UABS_G0 = 268435719

        AARCH64_MOVW_UABS_G0_NC = 268435720

        AARCH64_MOVW_UABS_G1 = 268435721

        AARCH64_MOVW_UABS_G1_NC = 268435722

        AARCH64_MOVW_UABS_G2 = 268435723

        AARCH64_MOVW_UABS_G2_NC = 268435724

        AARCH64_MOVW_UABS_G3 = 268435725

        AARCH64_MOVW_SABS_G0 = 268435726

        AARCH64_MOVW_SABS_G1 = 268435727

        AARCH64_MOVW_SABS_G2 = 268435728

        AARCH64_LD_PREL_LO19 = 268435729

        AARCH64_ADR_PREL_LO21 = 268435730

        AARCH64_ADR_PREL_PG_HI21 = 268435731

        AARCH64_ADR_PREL_PG_HI21_NC = 268435732

        AARCH64_ADD_ABS_LO12_NC = 268435733

        AARCH64_LDST8_ABS_LO12_NC = 268435734

        AARCH64_TSTBR14 = 268435735

        AARCH64_CONDBR19 = 268435736

        AARCH64_JUMP26 = 268435738

        AARCH64_CALL26 = 268435739

        AARCH64_LDST16_ABS_LO12_NC = 268435740

        AARCH64_LDST32_ABS_LO12_NC = 268435741

        AARCH64_LDST64_ABS_LO12_NC = 268435742

        AARCH64_MOVW_PREL_G0 = 268435743

        AARCH64_MOVW_PREL_G0_NC = 268435744

        AARCH64_MOVW_PREL_G1 = 268435745

        AARCH64_MOVW_PREL_G1_NC = 268435746

        AARCH64_MOVW_PREL_G2 = 268435747

        AARCH64_MOVW_PREL_G2_NC = 268435748

        AARCH64_MOVW_PREL_G3 = 268435749

        AARCH64_LDST128_ABS_LO12_NC = 268435755

        AARCH64_MOVW_GOTOFF_G0 = 268435756

        AARCH64_MOVW_GOTOFF_G0_NC = 268435757

        AARCH64_MOVW_GOTOFF_G1 = 268435758

        AARCH64_MOVW_GOTOFF_G1_NC = 268435759

        AARCH64_MOVW_GOTOFF_G2 = 268435760

        AARCH64_MOVW_GOTOFF_G2_NC = 268435761

        AARCH64_MOVW_GOTOFF_G3 = 268435762

        AARCH64_GOTREL64 = 268435763

        AARCH64_GOTREL32 = 268435764

        AARCH64_GOT_LD_PREL19 = 268435765

        AARCH64_LD64_GOTOFF_LO15 = 268435766

        AARCH64_ADR_GOT_PAGE = 268435767

        AARCH64_LD64_GOT_LO12_NC = 268435768

        AARCH64_LD64_GOTPAGE_LO15 = 268435769

        AARCH64_TLSGD_ADR_PREL21 = 268435968

        AARCH64_TLSGD_ADR_PAGE21 = 268435969

        AARCH64_TLSGD_ADD_LO12_NC = 268435970

        AARCH64_TLSGD_MOVW_G1 = 268435971

        AARCH64_TLSGD_MOVW_G0_NC = 268435972

        AARCH64_TLSLD_ADR_PREL21 = 268435973

        AARCH64_TLSLD_ADR_PAGE21 = 268435974

        AARCH64_TLSLD_ADD_LO12_NC = 268435975

        AARCH64_TLSLD_MOVW_G1 = 268435976

        AARCH64_TLSLD_MOVW_G0_NC = 268435977

        AARCH64_TLSLD_LD_PREL19 = 268435978

        AARCH64_TLSLD_MOVW_DTPREL_G2 = 268435979

        AARCH64_TLSLD_MOVW_DTPREL_G1 = 268435980

        AARCH64_TLSLD_MOVW_DTPREL_G1_NC = 268435981

        AARCH64_TLSLD_MOVW_DTPREL_G0 = 268435982

        AARCH64_TLSLD_MOVW_DTPREL_G0_NC = 268435983

        AARCH64_TLSLD_ADD_DTPREL_HI12 = 268435984

        AARCH64_TLSLD_ADD_DTPREL_LO12 = 268435985

        AARCH64_TLSLD_ADD_DTPREL_LO12_NC = 268435986

        AARCH64_TLSLD_LDST8_DTPREL_LO12 = 268435987

        AARCH64_TLSLD_LDST8_DTPREL_LO12_NC = 268435988

        AARCH64_TLSLD_LDST16_DTPREL_LO12 = 268435989

        AARCH64_TLSLD_LDST16_DTPREL_LO12_NC = 268435990

        AARCH64_TLSLD_LDST32_DTPREL_LO12 = 268435991

        AARCH64_TLSLD_LDST32_DTPREL_LO12_NC = 268435992

        AARCH64_TLSLD_LDST64_DTPREL_LO12 = 268435993

        AARCH64_TLSLD_LDST64_DTPREL_LO12_NC = 268435994

        AARCH64_TLSIE_MOVW_GOTTPREL_G1 = 268435995

        AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC = 268435996

        AARCH64_TLSIE_ADR_GOTTPREL_PAGE21 = 268435997

        AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC = 268435998

        AARCH64_TLSIE_LD_GOTTPREL_PREL19 = 268435999

        AARCH64_TLSLE_MOVW_TPREL_G2 = 268436000

        AARCH64_TLSLE_MOVW_TPREL_G1 = 268436001

        AARCH64_TLSLE_MOVW_TPREL_G1_NC = 268436002

        AARCH64_TLSLE_MOVW_TPREL_G0 = 268436003

        AARCH64_TLSLE_MOVW_TPREL_G0_NC = 268436004

        AARCH64_TLSLE_ADD_TPREL_HI12 = 268436005

        AARCH64_TLSLE_ADD_TPREL_LO12 = 268436006

        AARCH64_TLSLE_ADD_TPREL_LO12_NC = 268436007

        AARCH64_TLSLE_LDST8_TPREL_LO12 = 268436008

        AARCH64_TLSLE_LDST8_TPREL_LO12_NC = 268436009

        AARCH64_TLSLE_LDST16_TPREL_LO12 = 268436010

        AARCH64_TLSLE_LDST16_TPREL_LO12_NC = 268436011

        AARCH64_TLSLE_LDST32_TPREL_LO12 = 268436012

        AARCH64_TLSLE_LDST32_TPREL_LO12_NC = 268436013

        AARCH64_TLSLE_LDST64_TPREL_LO12 = 268436014

        AARCH64_TLSLE_LDST64_TPREL_LO12_NC = 268436015

        AARCH64_TLSDESC_LD_PREL19 = 268436016

        AARCH64_TLSDESC_ADR_PREL21 = 268436017

        AARCH64_TLSDESC_ADR_PAGE21 = 268436018

        AARCH64_TLSDESC_LD64_LO12_NC = 268436019

        AARCH64_TLSDESC_ADD_LO12_NC = 268436020

        AARCH64_TLSDESC_OFF_G1 = 268436021

        AARCH64_TLSDESC_OFF_G0_NC = 268436022

        AARCH64_TLSDESC_LDR = 268436023

        AARCH64_TLSDESC_ADD = 268436024

        AARCH64_TLSDESC_CALL = 268436025

        AARCH64_TLSLE_LDST128_TPREL_LO12 = 268436026

        AARCH64_TLSLE_LDST128_TPREL_LO12_NC = 268436027

        AARCH64_TLSLD_LDST128_DTPREL_LO12 = 268436028

        AARCH64_TLSLD_LDST128_DTPREL_LO12_NC = 268436029

        AARCH64_COPY = 268436480

        AARCH64_GLOB_DAT = 268436481

        AARCH64_JUMP_SLOT = 268436482

        AARCH64_RELATIVE = 268436483

        AARCH64_TLS_DTPREL64 = 268436484

        AARCH64_TLS_DTPMOD64 = 268436485

        AARCH64_TLS_TPREL64 = 268436486

        AARCH64_TLSDESC = 268436487

        AARCH64_IRELATIVE = 268436488

        ARM_NONE = 402653184

        ARM_PC24 = 402653185

        ARM_ABS32 = 402653186

        ARM_REL32 = 402653187

        ARM_LDR_PC_G0 = 402653188

        ARM_ABS16 = 402653189

        ARM_ABS12 = 402653190

        ARM_THM_ABS5 = 402653191

        ARM_ABS8 = 402653192

        ARM_SBREL32 = 402653193

        ARM_THM_CALL = 402653194

        ARM_THM_PC8 = 402653195

        ARM_BREL_ADJ = 402653196

        ARM_TLS_DESC = 402653197

        ARM_THM_SWI8 = 402653198

        ARM_XPC25 = 402653199

        ARM_THM_XPC22 = 402653200

        ARM_TLS_DTPMOD32 = 402653201

        ARM_TLS_DTPOFF32 = 402653202

        ARM_TLS_TPOFF32 = 402653203

        ARM_COPY = 402653204

        ARM_GLOB_DAT = 402653205

        ARM_JUMP_SLOT = 402653206

        ARM_RELATIVE = 402653207

        ARM_GOTOFF32 = 402653208

        ARM_BASE_PREL = 402653209

        ARM_GOT_BREL = 402653210

        ARM_PLT32 = 402653211

        ARM_CALL = 402653212

        ARM_JUMP24 = 402653213

        ARM_THM_JUMP24 = 402653214

        ARM_BASE_ABS = 402653215

        ARM_ALU_PCREL_7_0 = 402653216

        ARM_ALU_PCREL_15_8 = 402653217

        ARM_ALU_PCREL_23_15 = 402653218

        ARM_LDR_SBREL_11_0_NC = 402653219

        ARM_ALU_SBREL_19_12_NC = 402653220

        ARM_ALU_SBREL_27_20_CK = 402653221

        ARM_TARGET1 = 402653222

        ARM_SBREL31 = 402653223

        ARM_V4BX = 402653224

        ARM_TARGET2 = 402653225

        ARM_PREL31 = 402653226

        ARM_MOVW_ABS_NC = 402653227

        ARM_MOVT_ABS = 402653228

        ARM_MOVW_PREL_NC = 402653229

        ARM_MOVT_PREL = 402653230

        ARM_THM_MOVW_ABS_NC = 402653231

        ARM_THM_MOVT_ABS = 402653232

        ARM_THM_MOVW_PREL_NC = 402653233

        ARM_THM_MOVT_PREL = 402653234

        ARM_THM_JUMP19 = 402653235

        ARM_THM_JUMP6 = 402653236

        ARM_THM_ALU_PREL_11_0 = 402653237

        ARM_THM_PC12 = 402653238

        ARM_ABS32_NOI = 402653239

        ARM_REL32_NOI = 402653240

        ARM_ALU_PC_G0_NC = 402653241

        ARM_ALU_PC_G0 = 402653242

        ARM_ALU_PC_G1_NC = 402653243

        ARM_ALU_PC_G1 = 402653244

        ARM_ALU_PC_G2 = 402653245

        ARM_LDR_PC_G1 = 402653246

        ARM_LDR_PC_G2 = 402653247

        ARM_LDRS_PC_G0 = 402653248

        ARM_LDRS_PC_G1 = 402653249

        ARM_LDRS_PC_G2 = 402653250

        ARM_LDC_PC_G0 = 402653251

        ARM_LDC_PC_G1 = 402653252

        ARM_LDC_PC_G2 = 402653253

        ARM_ALU_SB_G0_NC = 402653254

        ARM_ALU_SB_G0 = 402653255

        ARM_ALU_SB_G1_NC = 402653256

        ARM_ALU_SB_G1 = 402653257

        ARM_ALU_SB_G2 = 402653258

        ARM_LDR_SB_G0 = 402653259

        ARM_LDR_SB_G1 = 402653260

        ARM_LDR_SB_G2 = 402653261

        ARM_LDRS_SB_G0 = 402653262

        ARM_LDRS_SB_G1 = 402653263

        ARM_LDRS_SB_G2 = 402653264

        ARM_LDC_SB_G0 = 402653265

        ARM_LDC_SB_G1 = 402653266

        ARM_LDC_SB_G2 = 402653267

        ARM_MOVW_BREL_NC = 402653268

        ARM_MOVT_BREL = 402653269

        ARM_MOVW_BREL = 402653270

        ARM_THM_MOVW_BREL_NC = 402653271

        ARM_THM_MOVT_BREL = 402653272

        ARM_THM_MOVW_BREL = 402653273

        ARM_TLS_GOTDESC = 402653274

        ARM_TLS_CALL = 402653275

        ARM_TLS_DESCSEQ = 402653276

        ARM_THM_TLS_CALL = 402653277

        ARM_PLT32_ABS = 402653278

        ARM_GOT_ABS = 402653279

        ARM_GOT_PREL = 402653280

        ARM_GOT_BREL12 = 402653281

        ARM_GOTOFF12 = 402653282

        ARM_GOTRELAX = 402653283

        ARM_GNU_VTENTRY = 402653284

        ARM_GNU_VTINHERIT = 402653285

        ARM_THM_JUMP11 = 402653286

        ARM_THM_JUMP8 = 402653287

        ARM_TLS_GD32 = 402653288

        ARM_TLS_LDM32 = 402653289

        ARM_TLS_LDO32 = 402653290

        ARM_TLS_IE32 = 402653291

        ARM_TLS_LE32 = 402653292

        ARM_TLS_LDO12 = 402653293

        ARM_TLS_LE12 = 402653294

        ARM_TLS_IE12GP = 402653295

        ARM_PRIVATE_0 = 402653296

        ARM_PRIVATE_1 = 402653297

        ARM_PRIVATE_2 = 402653298

        ARM_PRIVATE_3 = 402653299

        ARM_PRIVATE_4 = 402653300

        ARM_PRIVATE_5 = 402653301

        ARM_PRIVATE_6 = 402653302

        ARM_PRIVATE_7 = 402653303

        ARM_PRIVATE_8 = 402653304

        ARM_PRIVATE_9 = 402653305

        ARM_PRIVATE_10 = 402653306

        ARM_PRIVATE_11 = 402653307

        ARM_PRIVATE_12 = 402653308

        ARM_PRIVATE_13 = 402653309

        ARM_PRIVATE_14 = 402653310

        ARM_PRIVATE_15 = 402653311

        ARM_ME_TOO = 402653312

        ARM_THM_TLS_DESCSEQ16 = 402653313

        ARM_THM_TLS_DESCSEQ32 = 402653314

        ARM_IRELATIVE = 402653344

        ARM_RXPC25 = 402653433

        ARM_RSBREL32 = 402653434

        ARM_THM_RPC22 = 402653435

        ARM_RREL32 = 402653436

        ARM_RPC24 = 402653437

        ARM_RBASE = 402653438

        HEX_NONE = 536870912

        HEX_B22_PCREL = 536870913

        HEX_B15_PCREL = 536870914

        HEX_B7_PCREL = 536870915

        HEX_LO16 = 536870916

        HEX_HI16 = 536870917

        HEX_32 = 536870918

        HEX_16 = 536870919

        HEX_8 = 536870920

        HEX_GPREL16_0 = 536870921

        HEX_GPREL16_1 = 536870922

        HEX_GPREL16_2 = 536870923

        HEX_GPREL16_3 = 536870924

        HEX_HL16 = 536870925

        HEX_B13_PCREL = 536870926

        HEX_B9_PCREL = 536870927

        HEX_B32_PCREL_X = 536870928

        HEX_32_6_X = 536870929

        HEX_B22_PCREL_X = 536870930

        HEX_B15_PCREL_X = 536870931

        HEX_B13_PCREL_X = 536870932

        HEX_B9_PCREL_X = 536870933

        HEX_B7_PCREL_X = 536870934

        HEX_16_X = 536870935

        HEX_12_X = 536870936

        HEX_11_X = 536870937

        HEX_10_X = 536870938

        HEX_9_X = 536870939

        HEX_8_X = 536870940

        HEX_7_X = 536870941

        HEX_6_X = 536870942

        HEX_32_PCREL = 536870943

        HEX_COPY = 536870944

        HEX_GLOB_DAT = 536870945

        HEX_JMP_SLOT = 536870946

        HEX_RELATIVE = 536870947

        HEX_PLT_B22_PCREL = 536870948

        HEX_GOTREL_LO16 = 536870949

        HEX_GOTREL_HI16 = 536870950

        HEX_GOTREL_32 = 536870951

        HEX_GOT_LO16 = 536870952

        HEX_GOT_HI16 = 536870953

        HEX_GOT_32 = 536870954

        HEX_GOT_16 = 536870955

        HEX_DTPMOD_32 = 536870956

        HEX_DTPREL_LO16 = 536870957

        HEX_DTPREL_HI16 = 536870958

        HEX_DTPREL_32 = 536870959

        HEX_DTPREL_16 = 536870960

        HEX_GD_PLT_B22_PCREL = 536870961

        HEX_GD_GOT_LO16 = 536870962

        HEX_GD_GOT_HI16 = 536870963

        HEX_GD_GOT_32 = 536870964

        HEX_GD_GOT_16 = 536870965

        HEX_IE_LO16 = 536870966

        HEX_IE_HI16 = 536870967

        HEX_IE_32 = 536870968

        HEX_IE_GOT_LO16 = 536870969

        HEX_IE_GOT_HI16 = 536870970

        HEX_IE_GOT_32 = 536870971

        HEX_IE_GOT_16 = 536870972

        HEX_TPREL_LO16 = 536870973

        HEX_TPREL_HI16 = 536870974

        HEX_TPREL_32 = 536870975

        HEX_TPREL_16 = 536870976

        HEX_6_PCREL_X = 536870977

        HEX_GOTREL_32_6_X = 536870978

        HEX_GOTREL_16_X = 536870979

        HEX_GOTREL_11_X = 536870980

        HEX_GOT_32_6_X = 536870981

        HEX_GOT_16_X = 536870982

        HEX_GOT_11_X = 536870983

        HEX_DTPREL_32_6_X = 536870984

        HEX_DTPREL_16_X = 536870985

        HEX_DTPREL_11_X = 536870986

        HEX_GD_GOT_32_6_X = 536870987

        HEX_GD_GOT_16_X = 536870988

        HEX_GD_GOT_11_X = 536870989

        HEX_IE_32_6_X = 536870990

        HEX_IE_16_X = 536870991

        HEX_IE_GOT_32_6_X = 536870992

        HEX_IE_GOT_16_X = 536870993

        HEX_IE_GOT_11_X = 536870994

        HEX_TPREL_32_6_X = 536870995

        HEX_TPREL_16_X = 536870996

        HEX_TPREL_11_X = 536870997

        HEX_LD_PLT_B22_PCREL = 536870998

        HEX_LD_GOT_LO16 = 536870999

        HEX_LD_GOT_HI16 = 536871000

        HEX_LD_GOT_32 = 536871001

        HEX_LD_GOT_16 = 536871002

        HEX_LD_GOT_32_6_X = 536871003

        HEX_LD_GOT_16_X = 536871004

        HEX_LD_GOT_11_X = 536871005

        X86_NONE = 671088640

        X86_32 = 671088641

        X86_PC32 = 671088642

        X86_GOT32 = 671088643

        X86_PLT32 = 671088644

        X86_COPY = 671088645

        X86_GLOB_DAT = 671088646

        X86_JUMP_SLOT = 671088647

        X86_RELATIVE = 671088648

        X86_GOTOFF = 671088649

        X86_GOTPC = 671088650

        X86_32PLT = 671088651

        X86_TLS_TPOFF = 671088654

        X86_TLS_IE = 671088655

        X86_TLS_GOTIE = 671088656

        X86_TLS_LE = 671088657

        X86_TLS_GD = 671088658

        X86_TLS_LDM = 671088659

        X86_16 = 671088660

        X86_PC16 = 671088661

        X86_8 = 671088662

        X86_PC8 = 671088663

        X86_TLS_GD_32 = 671088664

        X86_TLS_GD_PUSH = 671088665

        X86_TLS_GD_CALL = 671088666

        X86_TLS_GD_POP = 671088667

        X86_TLS_LDM_32 = 671088668

        X86_TLS_LDM_PUSH = 671088669

        X86_TLS_LDM_CALL = 671088670

        X86_TLS_LDM_POP = 671088671

        X86_TLS_LDO_32 = 671088672

        X86_TLS_IE_32 = 671088673

        X86_TLS_LE_32 = 671088674

        X86_TLS_DTPMOD32 = 671088675

        X86_TLS_DTPOFF32 = 671088676

        X86_TLS_TPOFF32 = 671088677

        X86_TLS_GOTDESC = 671088679

        X86_TLS_DESC_CALL = 671088680

        X86_TLS_DESC = 671088681

        X86_IRELATIVE = 671088682

        LARCH_NONE = 805306368

        LARCH_32 = 805306369

        LARCH_64 = 805306370

        LARCH_RELATIVE = 805306371

        LARCH_COPY = 805306372

        LARCH_JUMP_SLOT = 805306373

        LARCH_TLS_DTPMOD32 = 805306374

        LARCH_TLS_DTPMOD64 = 805306375

        LARCH_TLS_DTPREL32 = 805306376

        LARCH_TLS_DTPREL64 = 805306377

        LARCH_TLS_TPREL32 = 805306378

        LARCH_TLS_TPREL64 = 805306379

        LARCH_IRELATIVE = 805306380

        LARCH_MARK_LA = 805306388

        LARCH_MARK_PCREL = 805306389

        LARCH_SOP_PUSH_PCREL = 805306390

        LARCH_SOP_PUSH_ABSOLUTE = 805306391

        LARCH_SOP_PUSH_DUP = 805306392

        LARCH_SOP_PUSH_GPREL = 805306393

        LARCH_SOP_PUSH_TLS_TPREL = 805306394

        LARCH_SOP_PUSH_TLS_GOT = 805306395

        LARCH_SOP_PUSH_TLS_GD = 805306396

        LARCH_SOP_PUSH_PLT_PCREL = 805306397

        LARCH_SOP_ASSERT = 805306398

        LARCH_SOP_NOT = 805306399

        LARCH_SOP_SUB = 805306400

        LARCH_SOP_SL = 805306401

        LARCH_SOP_SR = 805306402

        LARCH_SOP_ADD = 805306403

        LARCH_SOP_AND = 805306404

        LARCH_SOP_IF_ELSE = 805306405

        LARCH_SOP_POP_32_S_10_5 = 805306406

        LARCH_SOP_POP_32_U_10_12 = 805306407

        LARCH_SOP_POP_32_S_10_12 = 805306408

        LARCH_SOP_POP_32_S_10_16 = 805306409

        LARCH_SOP_POP_32_S_10_16_S2 = 805306410

        LARCH_SOP_POP_32_S_5_20 = 805306411

        LARCH_SOP_POP_32_S_0_5_10_16_S2 = 805306412

        LARCH_SOP_POP_32_S_0_10_10_16_S2 = 805306413

        LARCH_SOP_POP_32_U = 805306414

        LARCH_ADD8 = 805306415

        LARCH_ADD16 = 805306416

        LARCH_ADD24 = 805306417

        LARCH_ADD32 = 805306418

        LARCH_ADD64 = 805306419

        LARCH_SUB8 = 805306420

        LARCH_SUB16 = 805306421

        LARCH_SUB24 = 805306422

        LARCH_SUB32 = 805306423

        LARCH_SUB64 = 805306424

        LARCH_GNU_VTINHERIT = 805306425

        LARCH_GNU_VTENTRY = 805306426

        LARCH_B16 = 805306432

        LARCH_B21 = 805306433

        LARCH_B26 = 805306434

        LARCH_ABS_HI20 = 805306435

        LARCH_ABS_LO12 = 805306436

        LARCH_ABS64_LO20 = 805306437

        LARCH_ABS64_HI12 = 805306438

        LARCH_PCALA_HI20 = 805306439

        LARCH_PCALA_LO12 = 805306440

        LARCH_PCALA64_LO20 = 805306441

        LARCH_PCALA64_HI12 = 805306442

        LARCH_GOT_PC_HI20 = 805306443

        LARCH_GOT_PC_LO12 = 805306444

        LARCH_GOT64_PC_LO20 = 805306445

        LARCH_GOT64_PC_HI12 = 805306446

        LARCH_GOT_HI20 = 805306447

        LARCH_GOT_LO12 = 805306448

        LARCH_GOT64_LO20 = 805306449

        LARCH_GOT64_HI12 = 805306450

        LARCH_TLS_LE_HI20 = 805306451

        LARCH_TLS_LE_LO12 = 805306452

        LARCH_TLS_LE64_LO20 = 805306453

        LARCH_TLS_LE64_HI12 = 805306454

        LARCH_TLS_IE_PC_HI20 = 805306455

        LARCH_TLS_IE_PC_LO12 = 805306456

        LARCH_TLS_IE64_PC_LO20 = 805306457

        LARCH_TLS_IE64_PC_HI12 = 805306458

        LARCH_TLS_IE_HI20 = 805306459

        LARCH_TLS_IE_LO12 = 805306460

        LARCH_TLS_IE64_LO20 = 805306461

        LARCH_TLS_IE64_HI12 = 805306462

        LARCH_TLS_LD_PC_HI20 = 805306463

        LARCH_TLS_LD_HI20 = 805306464

        LARCH_TLS_GD_PC_HI20 = 805306465

        LARCH_TLS_GD_HI20 = 805306466

        LARCH_32_PCREL = 805306467

        LARCH_RELAX = 805306468

        LARCH_ALIGN = 805306470

        LARCH_PCREL20_S2 = 805306471

        LARCH_ADD6 = 805306473

        LARCH_SUB6 = 805306474

        LARCH_ADD_ULEB128 = 805306475

        LARCH_SUB_ULEB128 = 805306476

        LARCH_64_PCREL = 805306477

        LARCH_CALL36 = 805306478

        LARCH_TLS_DESC32 = 805306381

        LARCH_TLS_DESC64 = 805306382

        LARCH_TLS_DESC_PC_HI20 = 805306479

        LARCH_TLS_DESC_PC_LO12 = 805306480

        LARCH_TLS_DESC64_PC_LO20 = 805306481

        LARCH_TLS_DESC64_PC_HI12 = 805306482

        LARCH_TLS_DESC_HI20 = 805306483

        LARCH_TLS_DESC_LO12 = 805306484

        LARCH_TLS_DESC64_LO20 = 805306485

        LARCH_TLS_DESC64_HI12 = 805306486

        LARCH_TLS_DESC_LD = 805306487

        LARCH_TLS_DESC_CALL = 805306488

        LARCH_TLS_LE_HI20_R = 805306489

        LARCH_TLS_LE_ADD_R = 805306490

        LARCH_TLS_LE_LO12_R = 805306491

        LARCH_TLS_LD_PCREL20_S2 = 805306492

        LARCH_TLS_GD_PCREL20_S2 = 805306493

        LARCH_TLS_DESC_PCREL20_S2 = 805306494

        MIPS_NONE = 939524096

        MIPS_16 = 939524097

        MIPS_32 = 939524098

        MIPS_REL32 = 939524099

        MIPS_26 = 939524100

        MIPS_HI16 = 939524101

        MIPS_LO16 = 939524102

        MIPS_GPREL16 = 939524103

        MIPS_LITERAL = 939524104

        MIPS_GOT16 = 939524105

        MIPS_PC16 = 939524106

        MIPS_CALL16 = 939524107

        MIPS_GPREL32 = 939524108

        MIPS_UNUSED1 = 939524109

        MIPS_UNUSED2 = 939524110

        MIPS_UNUSED3 = 939524111

        MIPS_SHIFT5 = 939524112

        MIPS_SHIFT6 = 939524113

        MIPS_64 = 939524114

        MIPS_GOT_DISP = 939524115

        MIPS_GOT_PAGE = 939524116

        MIPS_GOT_OFST = 939524117

        MIPS_GOT_HI16 = 939524118

        MIPS_GOT_LO16 = 939524119

        MIPS_SUB = 939524120

        MIPS_INSERT_A = 939524121

        MIPS_INSERT_B = 939524122

        MIPS_DELETE = 939524123

        MIPS_HIGHER = 939524124

        MIPS_HIGHEST = 939524125

        MIPS_CALL_HI16 = 939524126

        MIPS_CALL_LO16 = 939524127

        MIPS_SCN_DISP = 939524128

        MIPS_REL16 = 939524129

        MIPS_ADD_IMMEDIATE = 939524130

        MIPS_PJUMP = 939524131

        MIPS_RELGOT = 939524132

        MIPS_JALR = 939524133

        MIPS_TLS_DTPMOD32 = 939524134

        MIPS_TLS_DTPREL32 = 939524135

        MIPS_TLS_DTPMOD64 = 939524136

        MIPS_TLS_DTPREL64 = 939524137

        MIPS_TLS_GD = 939524138

        MIPS_TLS_LDM = 939524139

        MIPS_TLS_DTPREL_HI16 = 939524140

        MIPS_TLS_DTPREL_LO16 = 939524141

        MIPS_TLS_GOTTPREL = 939524142

        MIPS_TLS_TPREL32 = 939524143

        MIPS_TLS_TPREL64 = 939524144

        MIPS_TLS_TPREL_HI16 = 939524145

        MIPS_TLS_TPREL_LO16 = 939524146

        MIPS_GLOB_DAT = 939524147

        MIPS_PC21_S2 = 939524156

        MIPS_PC26_S2 = 939524157

        MIPS_PC18_S3 = 939524158

        MIPS_PC19_S2 = 939524159

        MIPS_PCHI16 = 939524160

        MIPS_PCLO16 = 939524161

        MIPS16_26 = 939524196

        MIPS16_GPREL = 939524197

        MIPS16_GOT16 = 939524198

        MIPS16_CALL16 = 939524199

        MIPS16_HI16 = 939524200

        MIPS16_LO16 = 939524201

        MIPS16_TLS_GD = 939524202

        MIPS16_TLS_LDM = 939524203

        MIPS16_TLS_DTPREL_HI16 = 939524204

        MIPS16_TLS_DTPREL_LO16 = 939524205

        MIPS16_TLS_GOTTPREL = 939524206

        MIPS16_TLS_TPREL_HI16 = 939524207

        MIPS16_TLS_TPREL_LO16 = 939524208

        MIPS_COPY = 939524222

        MIPS_JUMP_SLOT = 939524223

        MICROMIPS_26_S1 = 939524229

        MICROMIPS_HI16 = 939524230

        MICROMIPS_LO16 = 939524231

        MICROMIPS_GPREL16 = 939524232

        MICROMIPS_LITERAL = 939524233

        MICROMIPS_GOT16 = 939524234

        MICROMIPS_PC7_S1 = 939524235

        MICROMIPS_PC10_S1 = 939524236

        MICROMIPS_PC16_S1 = 939524237

        MICROMIPS_CALL16 = 939524238

        MICROMIPS_GOT_DISP = 939524241

        MICROMIPS_GOT_PAGE = 939524242

        MICROMIPS_GOT_OFST = 939524243

        MICROMIPS_GOT_HI16 = 939524244

        MICROMIPS_GOT_LO16 = 939524245

        MICROMIPS_SUB = 939524246

        MICROMIPS_HIGHER = 939524247

        MICROMIPS_HIGHEST = 939524248

        MICROMIPS_CALL_HI16 = 939524249

        MICROMIPS_CALL_LO16 = 939524250

        MICROMIPS_SCN_DISP = 939524251

        MICROMIPS_JALR = 939524252

        MICROMIPS_HI0_LO16 = 939524253

        MICROMIPS_TLS_GD = 939524258

        MICROMIPS_TLS_LDM = 939524259

        MICROMIPS_TLS_DTPREL_HI16 = 939524260

        MICROMIPS_TLS_DTPREL_LO16 = 939524261

        MICROMIPS_TLS_GOTTPREL = 939524262

        MICROMIPS_TLS_TPREL_HI16 = 939524265

        MICROMIPS_TLS_TPREL_LO16 = 939524266

        MICROMIPS_GPREL7_S2 = 939524268

        MICROMIPS_PC23_S2 = 939524269

        MICROMIPS_PC21_S2 = 939524270

        MICROMIPS_PC26_S2 = 939524271

        MICROMIPS_PC18_S3 = 939524272

        MICROMIPS_PC19_S2 = 939524273

        MIPS_NUM = 939524314

        MIPS_PC32 = 939524344

        MIPS_EH = 939524345

        PPC_NONE = 1073741824

        PPC_ADDR32 = 1073741825

        PPC_ADDR24 = 1073741826

        PPC_ADDR16 = 1073741827

        PPC_ADDR16_LO = 1073741828

        PPC_ADDR16_HI = 1073741829

        PPC_ADDR16_HA = 1073741830

        PPC_ADDR14 = 1073741831

        PPC_ADDR14_BRTAKEN = 1073741832

        PPC_ADDR14_BRNTAKEN = 1073741833

        PPC_REL24 = 1073741834

        PPC_REL14 = 1073741835

        PPC_REL14_BRTAKEN = 1073741836

        PPC_REL14_BRNTAKEN = 1073741837

        PPC_GOT16 = 1073741838

        PPC_GOT16_LO = 1073741839

        PPC_GOT16_HI = 1073741840

        PPC_GOT16_HA = 1073741841

        PPC_PLTREL24 = 1073741842

        PPC_JMP_SLOT = 1073741845

        PPC_RELATIVE = 1073741846

        PPC_LOCAL24PC = 1073741847

        PPC_REL32 = 1073741850

        PPC_TLS = 1073741891

        PPC_DTPMOD32 = 1073741892

        PPC_TPREL16 = 1073741893

        PPC_TPREL16_LO = 1073741894

        PPC_TPREL16_HI = 1073741895

        PPC_TPREL16_HA = 1073741896

        PPC_TPREL32 = 1073741897

        PPC_DTPREL16 = 1073741898

        PPC_DTPREL16_LO = 1073741899

        PPC_DTPREL16_HI = 1073741900

        PPC_DTPREL16_HA = 1073741901

        PPC_DTPREL32 = 1073741902

        PPC_GOT_TLSGD16 = 1073741903

        PPC_GOT_TLSGD16_LO = 1073741904

        PPC_GOT_TLSGD16_HI = 1073741905

        PPC_GOT_TLSGD16_HA = 1073741906

        PPC_GOT_TLSLD16 = 1073741907

        PPC_GOT_TLSLD16_LO = 1073741908

        PPC_GOT_TLSLD16_HI = 1073741909

        PPC_GOT_TLSLD16_HA = 1073741910

        PPC_GOT_TPREL16 = 1073741911

        PPC_GOT_TPREL16_LO = 1073741912

        PPC_GOT_TPREL16_HI = 1073741913

        PPC_GOT_TPREL16_HA = 1073741914

        PPC_GOT_DTPREL16 = 1073741915

        PPC_GOT_DTPREL16_LO = 1073741916

        PPC_GOT_DTPREL16_HI = 1073741917

        PPC_GOT_DTPREL16_HA = 1073741918

        PPC_TLSGD = 1073741919

        PPC_TLSLD = 1073741920

        PPC_REL16 = 1073742073

        PPC_REL16_LO = 1073742074

        PPC_REL16_HI = 1073742075

        PPC_REL16_HA = 1073742076

        PPC64_NONE = 1207959552

        PPC64_ADDR32 = 1207959553

        PPC64_ADDR24 = 1207959554

        PPC64_ADDR16 = 1207959555

        PPC64_ADDR16_LO = 1207959556

        PPC64_ADDR16_HI = 1207959557

        PPC64_ADDR16_HA = 1207959558

        PPC64_ADDR14 = 1207959559

        PPC64_ADDR14_BRTAKEN = 1207959560

        PPC64_ADDR14_BRNTAKEN = 1207959561

        PPC64_REL24 = 1207959562

        PPC64_REL14 = 1207959563

        PPC64_REL14_BRTAKEN = 1207959564

        PPC64_REL14_BRNTAKEN = 1207959565

        PPC64_GOT16 = 1207959566

        PPC64_GOT16_LO = 1207959567

        PPC64_GOT16_HI = 1207959568

        PPC64_GOT16_HA = 1207959569

        PPC64_JMP_SLOT = 1207959573

        PPC64_RELATIVE = 1207959574

        PPC64_REL32 = 1207959578

        PPC64_ADDR64 = 1207959590

        PPC64_ADDR16_HIGHER = 1207959591

        PPC64_ADDR16_HIGHERA = 1207959592

        PPC64_ADDR16_HIGHEST = 1207959593

        PPC64_ADDR16_HIGHESTA = 1207959594

        PPC64_REL64 = 1207959596

        PPC64_TOC16 = 1207959599

        PPC64_TOC16_LO = 1207959600

        PPC64_TOC16_HI = 1207959601

        PPC64_TOC16_HA = 1207959602

        PPC64_TOC = 1207959603

        PPC64_ADDR16_DS = 1207959608

        PPC64_ADDR16_LO_DS = 1207959609

        PPC64_GOT16_DS = 1207959610

        PPC64_GOT16_LO_DS = 1207959611

        PPC64_TOC16_DS = 1207959615

        PPC64_TOC16_LO_DS = 1207959616

        PPC64_TLS = 1207959619

        PPC64_DTPMOD64 = 1207959620

        PPC64_TPREL16 = 1207959621

        PPC64_TPREL16_LO = 1207959622

        PPC64_TPREL16_HI = 1207959623

        PPC64_TPREL16_HA = 1207959624

        PPC64_TPREL64 = 1207959625

        PPC64_DTPREL16 = 1207959626

        PPC64_DTPREL16_LO = 1207959627

        PPC64_DTPREL16_HI = 1207959628

        PPC64_DTPREL16_HA = 1207959629

        PPC64_DTPREL64 = 1207959630

        PPC64_GOT_TLSGD16 = 1207959631

        PPC64_GOT_TLSGD16_LO = 1207959632

        PPC64_GOT_TLSGD16_HI = 1207959633

        PPC64_GOT_TLSGD16_HA = 1207959634

        PPC64_GOT_TLSLD16 = 1207959635

        PPC64_GOT_TLSLD16_LO = 1207959636

        PPC64_GOT_TLSLD16_HI = 1207959637

        PPC64_GOT_TLSLD16_HA = 1207959638

        PPC64_GOT_TPREL16_DS = 1207959639

        PPC64_GOT_TPREL16_LO_DS = 1207959640

        PPC64_GOT_TPREL16_HI = 1207959641

        PPC64_GOT_TPREL16_HA = 1207959642

        PPC64_GOT_DTPREL16_DS = 1207959643

        PPC64_GOT_DTPREL16_LO_DS = 1207959644

        PPC64_GOT_DTPREL16_HI = 1207959645

        PPC64_GOT_DTPREL16_HA = 1207959646

        PPC64_TPREL16_DS = 1207959647

        PPC64_TPREL16_LO_DS = 1207959648

        PPC64_TPREL16_HIGHER = 1207959649

        PPC64_TPREL16_HIGHERA = 1207959650

        PPC64_TPREL16_HIGHEST = 1207959651

        PPC64_TPREL16_HIGHESTA = 1207959652

        PPC64_DTPREL16_DS = 1207959653

        PPC64_DTPREL16_LO_DS = 1207959654

        PPC64_DTPREL16_HIGHER = 1207959655

        PPC64_DTPREL16_HIGHERA = 1207959656

        PPC64_DTPREL16_HIGHEST = 1207959657

        PPC64_DTPREL16_HIGHESTA = 1207959658

        PPC64_TLSGD = 1207959659

        PPC64_TLSLD = 1207959660

        PPC64_REL16 = 1207959801

        PPC64_REL16_LO = 1207959802

        PPC64_REL16_HI = 1207959803

        PPC64_REL16_HA = 1207959804

        SPARC_NONE = 1342177280

        SPARC_8 = 1342177281

        SPARC_16 = 1342177282

        SPARC_32 = 1342177283

        SPARC_DISP8 = 1342177284

        SPARC_DISP16 = 1342177285

        SPARC_DISP32 = 1342177286

        SPARC_WDISP30 = 1342177287

        SPARC_WDISP22 = 1342177288

        SPARC_HI22 = 1342177289

        SPARC_22 = 1342177290

        SPARC_13 = 1342177291

        SPARC_LO10 = 1342177292

        SPARC_GOT10 = 1342177293

        SPARC_GOT13 = 1342177294

        SPARC_GOT22 = 1342177295

        SPARC_PC10 = 1342177296

        SPARC_PC22 = 1342177297

        SPARC_WPLT30 = 1342177298

        SPARC_COPY = 1342177299

        SPARC_GLOB_DAT = 1342177300

        SPARC_JMP_SLOT = 1342177301

        SPARC_RELATIVE = 1342177302

        SPARC_UA32 = 1342177303

        SPARC_PLT32 = 1342177304

        SPARC_HIPLT22 = 1342177305

        SPARC_LOPLT10 = 1342177306

        SPARC_PCPLT32 = 1342177307

        SPARC_PCPLT22 = 1342177308

        SPARC_PCPLT10 = 1342177309

        SPARC_10 = 1342177310

        SPARC_11 = 1342177311

        SPARC_64 = 1342177312

        SPARC_OLO10 = 1342177313

        SPARC_HH22 = 1342177314

        SPARC_HM10 = 1342177315

        SPARC_LM22 = 1342177316

        SPARC_PC_HH22 = 1342177317

        SPARC_PC_HM10 = 1342177318

        SPARC_PC_LM22 = 1342177319

        SPARC_WDISP16 = 1342177320

        SPARC_WDISP19 = 1342177321

        SPARC_7 = 1342177323

        SPARC_5 = 1342177324

        SPARC_6 = 1342177325

        SPARC_DISP64 = 1342177326

        SPARC_PLT64 = 1342177327

        SPARC_HIX22 = 1342177328

        SPARC_LOX10 = 1342177329

        SPARC_H44 = 1342177330

        SPARC_M44 = 1342177331

        SPARC_L44 = 1342177332

        SPARC_REGISTER = 1342177333

        SPARC_UA64 = 1342177334

        SPARC_UA16 = 1342177335

        SPARC_TLS_GD_HI22 = 1342177336

        SPARC_TLS_GD_LO10 = 1342177337

        SPARC_TLS_GD_ADD = 1342177338

        SPARC_TLS_GD_CALL = 1342177339

        SPARC_TLS_LDM_HI22 = 1342177340

        SPARC_TLS_LDM_LO10 = 1342177341

        SPARC_TLS_LDM_ADD = 1342177342

        SPARC_TLS_LDM_CALL = 1342177343

        SPARC_TLS_LDO_HIX22 = 1342177344

        SPARC_TLS_LDO_LOX10 = 1342177345

        SPARC_TLS_LDO_ADD = 1342177346

        SPARC_TLS_IE_HI22 = 1342177347

        SPARC_TLS_IE_LO10 = 1342177348

        SPARC_TLS_IE_LD = 1342177349

        SPARC_TLS_IE_LDX = 1342177350

        SPARC_TLS_IE_ADD = 1342177351

        SPARC_TLS_LE_HIX22 = 1342177352

        SPARC_TLS_LE_LOX10 = 1342177353

        SPARC_TLS_DTPMOD32 = 1342177354

        SPARC_TLS_DTPMOD64 = 1342177355

        SPARC_TLS_DTPOFF32 = 1342177356

        SPARC_TLS_DTPOFF64 = 1342177357

        SPARC_TLS_TPOFF32 = 1342177358

        SPARC_TLS_TPOFF64 = 1342177359

        SPARC_GOTDATA_HIX22 = 1342177360

        SPARC_GOTDATA_LOX10 = 1342177361

        SPARC_GOTDATA_OP_HIX22 = 1342177362

        SPARC_GOTDATA_OP_LOX10 = 1342177363

        SPARC_GOTDATA_OP = 1342177364

        SYSZ_NONE = 1476395008

        SYSZ_8 = 1476395009

        SYSZ_12 = 1476395010

        SYSZ_16 = 1476395011

        SYSZ_32 = 1476395012

        SYSZ_PC32 = 1476395013

        SYSZ_GOT12 = 1476395014

        SYSZ_GOT32 = 1476395015

        SYSZ_PLT32 = 1476395016

        SYSZ_COPY = 1476395017

        SYSZ_GLOB_DAT = 1476395018

        SYSZ_JMP_SLOT = 1476395019

        SYSZ_RELATIVE = 1476395020

        SYSZ_GOTOFF = 1476395021

        SYSZ_GOTPC = 1476395022

        SYSZ_GOT16 = 1476395023

        SYSZ_PC16 = 1476395024

        SYSZ_PC16DBL = 1476395025

        SYSZ_PLT16DBL = 1476395026

        SYSZ_PC32DBL = 1476395027

        SYSZ_PLT32DBL = 1476395028

        SYSZ_GOTPCDBL = 1476395029

        SYSZ_64 = 1476395030

        SYSZ_PC64 = 1476395031

        SYSZ_GOT64 = 1476395032

        SYSZ_PLT64 = 1476395033

        SYSZ_GOTENT = 1476395034

        SYSZ_GOTOFF16 = 1476395035

        SYSZ_GOTOFF64 = 1476395036

        SYSZ_GOTPLT12 = 1476395037

        SYSZ_GOTPLT16 = 1476395038

        SYSZ_GOTPLT32 = 1476395039

        SYSZ_GOTPLT64 = 1476395040

        SYSZ_GOTPLTENT = 1476395041

        SYSZ_PLTOFF16 = 1476395042

        SYSZ_PLTOFF32 = 1476395043

        SYSZ_PLTOFF64 = 1476395044

        SYSZ_TLS_LOAD = 1476395045

        SYSZ_TLS_GDCALL = 1476395046

        SYSZ_TLS_LDCALL = 1476395047

        SYSZ_TLS_GD32 = 1476395048

        SYSZ_TLS_GD64 = 1476395049

        SYSZ_TLS_GOTIE12 = 1476395050

        SYSZ_TLS_GOTIE32 = 1476395051

        SYSZ_TLS_GOTIE64 = 1476395052

        SYSZ_TLS_LDM32 = 1476395053

        SYSZ_TLS_LDM64 = 1476395054

        SYSZ_TLS_IE32 = 1476395055

        SYSZ_TLS_IE64 = 1476395056

        SYSZ_TLS_IEENT = 1476395057

        SYSZ_TLS_LE32 = 1476395058

        SYSZ_TLS_LE64 = 1476395059

        SYSZ_TLS_LDO32 = 1476395060

        SYSZ_TLS_LDO64 = 1476395061

        SYSZ_TLS_DTPMOD = 1476395062

        SYSZ_TLS_DTPOFF = 1476395063

        SYSZ_TLS_TPOFF = 1476395064

        SYSZ_20 = 1476395065

        SYSZ_GOT20 = 1476395066

        SYSZ_GOTPLT20 = 1476395067

        SYSZ_TLS_GOTIE20 = 1476395068

        SYSZ_IRELATIVE = 1476395069

        RISCV_NONE = 1610612736

        RISCV_32 = 1610612737

        RISCV_64 = 1610612738

        RISCV_RELATIVE = 1610612739

        RISCV_COPY = 1610612740

        RISCV_JUMP_SLOT = 1610612741

        RISCV_TLS_DTPMOD32 = 1610612742

        RISCV_TLS_DTPMOD64 = 1610612743

        RISCV_TLS_DTPREL32 = 1610612744

        RISCV_TLS_DTPREL64 = 1610612745

        RISCV_TLS_TPREL32 = 1610612746

        RISCV_TLS_TPREL64 = 1610612747

        RISCV_TLSDESC = 1610612748

        RISCV_BRANCH = 1610612752

        RISCV_JAL = 1610612753

        RISCV_CALL = 1610612754

        RISCV_CALL_PLT = 1610612755

        RISCV_GOT_HI20 = 1610612756

        RISCV_TLS_GOT_HI20 = 1610612757

        RISCV_TLS_GD_HI20 = 1610612758

        RISCV_PCREL_HI20 = 1610612759

        RISCV_PCREL_LO12_I = 1610612760

        RISCV_PCREL_LO12_S = 1610612761

        RISCV_HI20 = 1610612762

        RISCV_LO12_I = 1610612763

        RISCV_LO12_S = 1610612764

        RISCV_TPREL_HI20 = 1610612765

        RISCV_TPREL_LO12_I = 1610612766

        RISCV_TPREL_LO12_S = 1610612767

        RISCV_TPREL_ADD = 1610612768

        RISCV_ADD8 = 1610612769

        RISCV_ADD16 = 1610612770

        RISCV_ADD32 = 1610612771

        RISCV_ADD64 = 1610612772

        RISCV_SUB8 = 1610612773

        RISCV_SUB16 = 1610612774

        RISCV_SUB32 = 1610612775

        RISCV_SUB64 = 1610612776

        RISCV_GOT32_PCREL = 1610612777

        RISCV_ALIGN = 1610612779

        RISCV_RVC_BRANCH = 1610612780

        RISCV_RVC_JUMP = 1610612781

        RISCV_RVC_LUI = 1610612782

        RISCV_RELAX = 1610612787

        RISCV_SUB6 = 1610612788

        RISCV_SET6 = 1610612789

        RISCV_SET8 = 1610612790

        RISCV_SET16 = 1610612791

        RISCV_SET32 = 1610612792

        RISCV_32_PCREL = 1610612793

        RISCV_IRELATIVE = 1610612794

        RISCV_PLT32 = 1610612795

        RISCV_SET_ULEB128 = 1610612796

        RISCV_SUB_ULEB128 = 1610612797

        RISCV_TLSDESC_HI20 = 1610612798

        RISCV_TLSDESC_LOAD_LO12 = 1610612799

        RISCV_TLSDESC_ADD_LO12 = 1610612800

        RISCV_TLSDESC_CALL = 1610612801

        BPF_NONE = 1744830464

        BPF_64_64 = 1744830465

        BPF_64_ABS64 = 1744830466

        BPF_64_ABS32 = 1744830467

        BPF_64_NODYLD32 = 1744830468

        BPF_64_32 = 1744830474

    class PURPOSE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Relocation.PURPOSE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        NONE = 0

        PLTGOT = 1

        DYNAMIC = 2

        OBJECT = 3

    class ENCODING(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Relocation.ENCODING: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        ANDROID_SLEB = 4

        REL = 1

        RELR = 3

        RELA = 2

    addend: int

    info: int

    purpose: lief.ELF.Relocation.PURPOSE

    type: lief.ELF.Relocation.TYPE

    @property
    def has_symbol(self) -> bool: ...

    symbol: lief.ELF.Symbol

    @property
    def has_section(self) -> bool: ...

    @property
    def section(self) -> Section: ...

    @property
    def symbol_table(self) -> Section: ...

    @property
    def is_rela(self) -> bool: ...

    @property
    def is_rel(self) -> bool: ...

    def r_info(self, clazz: Header.CLASS) -> int: ...

    @property
    def is_relatively_encoded(self) -> bool: ...

    @property
    def is_android_packed(self) -> bool: ...

    @property
    def encoding(self) -> Relocation.ENCODING: ...

    def resolve(self, base_address: int = 0) -> Union[int, lief.lief_errors]: ...

    def __str__(self) -> str: ...

class Section(lief.Section):
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, name: str, type: Section.TYPE = Section.TYPE.PROGBITS) -> None: ...

    class it_segments:
        def __getitem__(self, arg: int, /) -> Segment: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Section.it_segments: ...

        def __next__(self) -> Segment: ...

    class FLAGS(enum.Flag):
        @staticmethod
        def from_value(arg: int, /) -> Section.FLAGS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        NONE = 0

        WRITE = 1

        ALLOC = 2

        EXECINSTR = 4

        MERGE = 16

        STRINGS = 32

        INFO_LINK = 64

        LINK_ORDER = 128

        OS_NONCONFORMING = 256

        GROUP = 512

        TLS = 1024

        COMPRESSED = 2048

        GNU_RETAIN = 2097152

        EXCLUDE = 2147483648

        XCORE_SHF_DP_SECTION = 4563402752

        XCORE_SHF_CP_SECTION = 4831838208

        X86_64_LARGE = 8858370048

        HEX_GPREL = 13153337344

        MIPS_NODUPES = 17196646400

        MIPS_NAMES = 17213423616

        MIPS_LOCAL = 17246978048

        MIPS_NOSTRIP = 17314086912

        MIPS_GPREL = 17448304640

        MIPS_MERGE = 17716740096

        MIPS_ADDR = 18253611008

        MIPS_STRING = 19327352832

        ARM_PURECODE = 22011707392

    class TYPE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Section.TYPE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        PROGBITS = 1

        SYMTAB = 2

        STRTAB = 3

        RELA = 4

        HASH = 5

        DYNAMIC = 6

        NOTE = 7

        NOBITS = 8

        REL = 9

        SHLIB = 10

        DYNSYM = 11

        INIT_ARRAY = 14

        FINI_ARRAY = 15

        PREINIT_ARRAY = 16

        GROUP = 17

        SYMTAB_SHNDX = 18

        RELR = 19

        ANDROID_REL = 1610612737

        ANDROID_RELA = 1610612738

        LLVM_ADDRSIG = 1879002115

        ANDROID_RELR = 1879047936

        GNU_ATTRIBUTES = 1879048181

        GNU_HASH = 1879048182

        GNU_VERDEF = 1879048189

        GNU_VERNEED = 1879048190

        GNU_VERSYM = 1879048191

        ARM_EXIDX = 6174015489

        ARM_PREEMPTMAP = 6174015490

        ARM_ATTRIBUTES = 6174015491

        ARM_DEBUGOVERLAY = 6174015492

        ARM_OVERLAYSECTION = 6174015493

        HEX_ORDERED = 10468982784

        X86_64_UNWIND = 10468982785

        MIPS_REGINFO = 14763950086

        MIPS_OPTIONS = 14763950093

        MIPS_ABIFLAGS = 14763950122

        RISCV_ATTRIBUTES = 19058917379

    def as_frame(self) -> Section: ...

    @property
    def is_frame(self) -> bool: ...

    type: lief.ELF.Section.TYPE

    flags: int

    @property
    def flags_list(self) -> list[Section.FLAGS]: ...

    file_offset: int

    @property
    def original_size(self) -> int: ...

    alignment: int

    information: int

    entry_size: int

    link: int

    @property
    def segments(self) -> Section.it_segments: ...

    def clear(self, value: int = 0) -> Section: ...

    def add(self, flag: Section.FLAGS) -> None: ...

    def remove(self, flag: Section.FLAGS) -> None: ...

    @overload
    def has(self, flag: Section.FLAGS) -> bool: ...

    @overload
    def has(self, segment: Segment) -> bool: ...

    def __iadd__(self, arg: Section.FLAGS, /) -> Section: ...

    def __isub__(self, arg: Section.FLAGS, /) -> Section: ...

    @overload
    def __contains__(self, arg: Section.FLAGS, /) -> bool: ...

    @overload
    def __contains__(self, arg: Segment, /) -> bool: ...

    def __str__(self) -> str: ...

class Segment(lief.Object):
    def __init__(self) -> None: ...

    class it_sections:
        def __getitem__(self, arg: int, /) -> Section: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Segment.it_sections: ...

        def __next__(self) -> Section: ...

    class TYPE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Segment.TYPE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        LOAD = 1

        DYNAMIC = 2

        INTERP = 3

        NOTE = 4

        SHLIB = 5

        PHDR = 6

        TLS = 7

        GNU_EH_FRAME = 1685382480

        GNU_STACK = 1685382481

        GNU_PROPERTY = 1685382483

        GNU_RELRO = 1685382482

        ARM_ARCHEXT = 10468982784

        ARM_EXIDX = 10468982785

        AARCH64_MEMTAG_MTE = 19058917378

        MIPS_REGINFO = 27648851968

        MIPS_RTPROC = 27648851969

        MIPS_OPTIONS = 27648851970

        MIPS_ABIFLAGS = 27648851971

        RISCV_ATTRIBUTES = 36238786563

    class FLAGS(enum.Flag):
        @staticmethod
        def from_value(arg: int, /) -> Segment.FLAGS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        R = 4

        W = 2

        X = 1

        NONE = 0

    @staticmethod
    def from_raw(arg: bytes, /) -> Union[Segment, lief.lief_errors]: ...

    type: lief.ELF.Segment.TYPE

    flags: lief.ELF.Segment.FLAGS

    file_offset: int

    virtual_address: int

    physical_address: int

    physical_size: int

    virtual_size: int

    alignment: int

    content: memoryview

    def add(self, flag: Segment.FLAGS) -> None: ...

    def remove(self, flag: Segment.FLAGS) -> None: ...

    @overload
    def has(self, flag: Segment.FLAGS) -> bool: ...

    @overload
    def has(self, section: Section) -> bool: ...

    @overload
    def has(self, section_name: str) -> bool: ...

    @property
    def sections(self) -> Segment.it_sections: ...

    def __iadd__(self, arg: Segment.FLAGS, /) -> Segment: ...

    def __isub__(self, arg: Segment.FLAGS, /) -> Segment: ...

    @overload
    def __contains__(self, arg: Segment.FLAGS, /) -> bool: ...

    @overload
    def __contains__(self, arg: Section, /) -> bool: ...

    @overload
    def __contains__(self, arg: str, /) -> bool: ...

    def __str__(self) -> str: ...

class StackSize(NoteGnuProperty.Property):
    @property
    def stack_size(self) -> int: ...

class Symbol(lief.Symbol):
    def __init__(self) -> None: ...

    class BINDING(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Symbol.BINDING: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        LOCAL = 0

        GLOBAL = 1

        WEAK = 2

        GNU_UNIQUE = 10

    class TYPE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Symbol.TYPE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        NOTYPE = 0

        OBJECT = 1

        FUNC = 2

        SECTION = 3

        FILE = 4

        COMMON = 5

        TLS = 6

        GNU_IFUNC = 10

    class VISIBILITY(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Symbol.VISIBILITY: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        DEFAULT = 0

        INTERNAL = 1

        HIDDEN = 2

        PROTECTED = 3

    @property
    def demangled_name(self) -> str: ...

    type: lief.ELF.Symbol.TYPE

    binding: lief.ELF.Symbol.BINDING

    information: int

    other: int

    visibility: lief.ELF.Symbol.VISIBILITY

    value: int

    size: int

    shndx: int

    @property
    def has_version(self) -> bool: ...

    @property
    def symbol_version(self) -> SymbolVersion: ...

    @property
    def section(self) -> Section: ...

    @property
    def is_static(self) -> bool: ...

    @property
    def is_function(self) -> bool: ...

    @property
    def is_variable(self) -> bool: ...

    exported: bool

    imported: bool

    def __str__(self) -> str: ...

class SymbolVersion(lief.Object):
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, arg: int, /) -> None: ...

    local: lief.ELF.SymbolVersion = ...

    value: int

    @property
    def has_auxiliary_version(self) -> bool: ...

    symbol_version_auxiliary: lief.ELF.SymbolVersionAux

    def __str__(self) -> str: ...

class SymbolVersionAux(lief.Object):
    name: Union[str, bytes]

    def __str__(self) -> str: ...

class SymbolVersionAuxRequirement(SymbolVersionAux):
    def __init__(self) -> None: ...

    hash: int

    flags: int

    other: int

    def __str__(self) -> str: ...

class SymbolVersionDefinition(lief.Object):
    class it_version_aux:
        def __getitem__(self, arg: int, /) -> SymbolVersionAux: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> SymbolVersionDefinition.it_version_aux: ...

        def __next__(self) -> SymbolVersionAux: ...

    version: int

    flags: int

    hash: int

    @property
    def ndx(self) -> int: ...

    @property
    def auxiliary_symbols(self) -> SymbolVersionDefinition.it_version_aux: ...

    def __str__(self) -> str: ...

class SymbolVersionRequirement(lief.Object):
    class it_aux_requirement:
        def __getitem__(self, arg: int, /) -> SymbolVersionAuxRequirement: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> SymbolVersionRequirement.it_aux_requirement: ...

        def __next__(self) -> SymbolVersionAuxRequirement: ...

    version: int

    name: str

    def get_auxiliary_symbols(self) -> SymbolVersionRequirement.it_aux_requirement: ...

    def add_auxiliary_requirement(self, arg: SymbolVersionAuxRequirement, /) -> SymbolVersionAuxRequirement: ...

    def __str__(self) -> str: ...

class SysvHash(lief.Object):
    def __init__(self) -> None: ...

    @property
    def nbucket(self) -> int: ...

    nchain: int

    @property
    def buckets(self) -> list[int]: ...

    @property
    def chains(self) -> list[int]: ...

    def __str__(self) -> str: ...

class X86Features(NoteGnuProperty.Property):
    @property
    def features(self) -> list[tuple[X86Features.FLAG, X86Features.FEATURE]]: ...

    class FLAG(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> X86Features.FLAG: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        NONE = 0

        NEEDED = 2

        USED = 1

    class FEATURE(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> X86Features.FEATURE: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        IBT = 1

        SHSTK = 2

        LAM_U48 = 3

        LAM_U57 = 4

        X86 = 5

        X87 = 6

        MMX = 7

        XMM = 8

        YMM = 9

        ZMM = 10

        FXSR = 11

        XSAVE = 12

        XSAVEOPT = 13

        XSAVEC = 14

        TMM = 15

        MASK = 16

class X86ISA(NoteGnuProperty.Property):
    @property
    def values(self) -> list[tuple[X86ISA.FLAG, X86ISA.ISA]]: ...

    class FLAG(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> X86ISA.FLAG: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        NONE = 0

        NEEDED = 2

        USED = 1

    class ISA(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> X86ISA.ISA: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        BASELINE = 1

        V2 = 2

        V3 = 3

        V4 = 4

        CMOV = 5

        FMA = 6

        I486 = 7

        I586 = 8

        I686 = 9

        SSE = 10

        SSE2 = 11

        SSE3 = 12

        SSSE3 = 13

        SSE4_1 = 14

        SSE4_2 = 15

        AVX = 16

        AVX2 = 17

        AVX512F = 18

        AVX512CD = 19

        AVX512ER = 20

        AVX512PF = 21

        AVX512VL = 22

        AVX512DQ = 23

        AVX512BW = 24

        AVX512_4FMAPS = 25

        AVX512_4VNNIW = 26

        AVX512_BITALG = 27

        AVX512_IFMA = 28

        AVX512_VBMI = 29

        AVX512_VBMI2 = 30

        AVX512_VNNI = 31

        AVX512_BF16 = 32

@overload
def parse(filename: str, config: ParserConfig = ...) -> Optional[Binary]: ...

@overload
def parse(raw: Sequence[int], config: ParserConfig = ...) -> Optional[Binary]: ...

@overload
def parse(obj: Union[io.IOBase | os.PathLike], config: ParserConfig = ...) -> Optional[Binary]: ...
