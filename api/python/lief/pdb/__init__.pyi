import enum
import os
from typing import Iterator, Optional, Union

from . import types as types
import lief


def load(path: str) -> Optional[DebugInfo]: ...

class BuildMetadata:
    class LANG(enum.Enum):
        C = 0

        CPP = 1

        FORTRAN = 2

        MASM = 3

        PASCAL_LANG = 4

        BASIC = 5

        COBOL = 6

        LINK = 7

        CVTRES = 8

        CVTPGD = 9

        CSHARP = 10

        VB = 11

        ILASM = 12

        JAVA = 13

        JSCRIPT = 14

        MSIL = 15

        HLSL = 16

        OBJC = 17

        OBJCPP = 18

        SWIFT = 19

        ALIASOBJ = 20

        RUST = 21

        GO = 22

        UNKNOWN = 255

    class CPU(enum.Enum):
        INTEL_8080 = 0

        INTEL_8086 = 1

        INTEL_80286 = 2

        INTEL_80386 = 3

        INTEL_80486 = 4

        PENTIUM = 5

        PENTIUMPRO = 6

        PENTIUM3 = 7

        MIPS = 16

        MIPS16 = 17

        MIPS32 = 18

        MIPS64 = 19

        MIPSI = 20

        MIPSII = 21

        MIPSIII = 22

        MIPSIV = 23

        MIPSV = 24

        M68000 = 32

        M68010 = 33

        M68020 = 34

        M68030 = 35

        M68040 = 36

        ALPHA = 48

        ALPHA_21164 = 49

        ALPHA_21164A = 50

        ALPHA_21264 = 51

        ALPHA_21364 = 52

        PPC601 = 64

        PPC603 = 65

        PPC604 = 66

        PPC620 = 67

        PPCFP = 68

        PPCBE = 69

        SH3 = 80

        SH3E = 81

        SH3DSP = 82

        SH4 = 83

        SHMEDIA = 84

        ARM3 = 96

        ARM4 = 97

        ARM4T = 98

        ARM5 = 99

        ARM5T = 100

        ARM6 = 101

        ARM_XMAC = 102

        ARM_WMMX = 103

        ARM7 = 104

        OMNI = 112

        IA64 = 128

        IA64_2 = 129

        CEE = 144

        AM33 = 160

        M32R = 176

        TRICORE = 192

        X64 = 208

        EBC = 224

        THUMB = 240

        ARMNT = 244

        ARM64 = 246

        HYBRID_X86ARM64 = 247

        ARM64EC = 248

        ARM64X = 249

        D3D11_SHADER = 256

        UNKNOWN = 255

    class version_t:
        major: int

        minor: int

        build: int

        qfe: int

    class build_info_t:
        cwd: str

        build_tool: str

        source_file: str

        pdb: str

        command_line: str

    @property
    def frontend_version(self) -> BuildMetadata.version_t: ...

    @property
    def backend_version(self) -> BuildMetadata.version_t: ...

    @property
    def version(self) -> str: ...

    @property
    def language(self) -> BuildMetadata.LANG: ...

    @property
    def target_cpu(self) -> BuildMetadata.CPU: ...

    @property
    def build_info(self) -> BuildMetadata.build_info_t | None: ...

    @property
    def env(self) -> list[str]: ...

    def __str__(self) -> str: ...

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

class DebugInfo(lief.DebugInfo):
    @property
    def age(self) -> int: ...

    @property
    def guid(self) -> str: ...

    @staticmethod
    def from_file(filepath: Union[str | os.PathLike]) -> Optional[DebugInfo]: ...

    def find_type(self, name: str) -> Optional[Type]: ...

    def find_public_symbol(self, name: str) -> Optional[PublicSymbol]: ...

    @property
    def public_symbols(self) -> Iterator[Optional[PublicSymbol]]: ...

    @property
    def compilation_units(self) -> Iterator[Optional[CompilationUnit]]: ...

    @property
    def types(self) -> Iterator[Optional[Type]]: ...

    def __str__(self) -> str: ...

class PublicSymbol:
    @property
    def name(self) -> str: ...

    @property
    def section_name(self) -> str: ...

    @property
    def RVA(self) -> int: ...

    @property
    def demangled_name(self) -> str: ...

    def __str__(self) -> str: ...

class CompilationUnit:
    @property
    def module_name(self) -> str: ...

    @property
    def object_filename(self) -> str: ...

    @property
    def sources(self) -> Iterator[str]: ...

    @property
    def functions(self) -> Iterator[Optional[Function]]: ...

    @property
    def build_metadata(self) -> Optional[BuildMetadata]: ...

    def __str__(self) -> str: ...

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

    def __str__(self) -> str: ...
