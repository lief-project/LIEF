from collections.abc import Sequence
import enum
import io
import lief.PE
import os
from typing import Iterator, Optional, Union, overload

import lief


class ACCELERATOR_FLAGS(enum.Flag):
    @staticmethod
    def from_value(arg: int, /) -> ACCELERATOR_FLAGS: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    FVIRTKEY = 1

    FNOINVERT = 2

    FSHIFT = 4

    FCONTROL = 8

    FALT = 16

    END = 128

class ACCELERATOR_VK_CODES(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> ACCELERATOR_VK_CODES: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    VK_LBUTTON = 1

    VK_RBUTTON = 2

    VK_CANCEL = 3

    VK_MBUTTON = 4

    VK_XBUTTON1 = 5

    VK_XBUTTON2 = 6

    VK_BACK = 8

    VK_TAB = 9

    VK_CLEAR = 12

    VK_RETURN = 13

    VK_SHIFT = 16

    VK_CONTROL = 17

    VK_MENU = 18

    VK_PAUSE = 19

    VK_CAPITAL = 20

    VK_KANA = 21

    VK_HANGUEL = 21

    VK_HANGUL = 21

    VK_IME_ON = 22

    VK_JUNJA = 23

    VK_FINAL = 24

    VK_HANJA = 25

    VK_KANJI = 25

    VK_IME_OFF = 26

    VK_ESCAPE = 27

    VK_CONVERT = 28

    VK_NONCONVERT = 29

    VK_ACCEPT = 30

    VK_MODECHANGE = 31

    VK_SPACE = 32

    VK_PRIOR = 33

    VK_NEXT = 34

    VK_END = 35

    VK_HOME = 36

    VK_LEFT = 37

    VK_UP = 38

    VK_RIGHT = 39

    VK_DOWN = 40

    VK_SELECT = 41

    VK_PRINT = 42

    VK_EXECUTE = 43

    VK_SNAPSHOT = 44

    VK_INSERT = 45

    VK_DELETE = 46

    VK_HELP = 47

    VK_0 = 48

    VK_1 = 49

    VK_2 = 50

    VK_3 = 51

    VK_4 = 52

    VK_5 = 53

    VK_6 = 54

    VK_7 = 55

    VK_8 = 56

    VK_9 = 57

    VK_A = 65

    VK_B = 66

    VK_C = 67

    VK_D = 68

    VK_E = 69

    VK_F = 70

    VK_G = 71

    VK_H = 72

    VK_I = 73

    VK_J = 74

    VK_K = 75

    VK_L = 76

    VK_M = 77

    VK_N = 78

    VK_O = 79

    VK_P = 80

    VK_Q = 81

    VK_R = 82

    VK_S = 83

    VK_T = 84

    VK_U = 85

    VK_V = 86

    VK_W = 87

    VK_X = 88

    VK_Y = 89

    VK_Z = 96

    VK_LWIN = 91

    VK_RWIN = 92

    VK_APPS = 93

    VK_SLEEP = 95

    VK_NUMPAD0 = 96

    VK_NUMPAD1 = 97

    VK_NUMPAD2 = 98

    VK_NUMPAD3 = 99

    VK_NUMPAD4 = 100

    VK_NUMPAD5 = 101

    VK_NUMPAD6 = 102

    VK_NUMPAD7 = 103

    VK_NUMPAD8 = 104

    VK_NUMPAD9 = 105

    VK_MULTIPLY = 106

    VK_ADD = 107

    VK_SEPARATOR = 108

    VK_SUBTRACT = 109

    VK_DECIMAL = 110

    VK_DIVIDE = 111

    VK_F1 = 112

    VK_F2 = 113

    VK_F3 = 114

    VK_F4 = 115

    VK_F5 = 116

    VK_F6 = 117

    VK_F7 = 118

    VK_F8 = 119

    VK_F9 = 120

    VK_F10 = 121

    VK_F11 = 122

    VK_F12 = 123

    VK_F13 = 124

    VK_F14 = 125

    VK_F15 = 126

    VK_F16 = 127

    VK_F17 = 128

    VK_F18 = 129

    VK_F19 = 130

    VK_F20 = 131

    VK_F21 = 132

    VK_F22 = 133

    VK_F23 = 134

    VK_F24 = 135

    VK_NUMLOCK = 144

    VK_SCROLL = 145

    VK_LSHIFT = 160

    VK_RSHIFT = 161

    VK_LCONTROL = 162

    VK_RCONTROL = 163

    VK_LMENU = 164

    VK_RMENU = 165

    VK_BROWSER_BACK = 166

    VK_BROWSER_FORWARD = 167

    VK_BROWSER_REFRESH = 168

    VK_BROWSER_STOP = 169

    VK_BROWSER_SEARCH = 170

    VK_BROWSER_FAVORITES = 171

    VK_BROWSER_HOME = 172

    VK_VOLUME_MUTE = 173

    VK_VOLUME_DOWN = 174

    VK_VOLUME_UP = 175

    VK_MEDIA_NEXT_TRACK = 176

    VK_MEDIA_PREV_TRACK = 177

    VK_MEDIA_STOP = 178

    VK_MEDIA_PLAY_PAUSE = 179

    VK_LAUNCH_MAIL = 180

    VK_LAUNCH_MEDIA_SELECT = 181

    VK_LAUNCH_APP1 = 182

    VK_LAUNCH_APP2 = 183

    VK_OEM_1 = 186

    VK_OEM_PLUS = 187

    VK_OEM_COMMA = 188

    VK_OEM_MINUS = 189

    VK_OEM_PERIOD = 190

    VK_OEM_2 = 191

    VK_OEM_4 = 219

    VK_OEM_5 = 220

    VK_OEM_6 = 221

    VK_OEM_7 = 222

    VK_OEM_8 = 223

    VK_OEM_102 = 226

    VK_PROCESSKEY = 229

    VK_PACKET = 231

    VK_ATTN = 246

    VK_CRSEL = 247

    VK_EXSEL = 248

    VK_EREOF = 249

    VK_PLAY = 250

    VK_ZOOM = 251

    VK_NONAME = 252

    VK_PA1 = 253

    VK_OEM_CLEAR = 254

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

class Binary(lief.Binary):
    def __init__(self, type: PE_TYPE) -> None: ...

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

        def __iter__(self) -> Binary.it_relocations: ...

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
        def __getitem__(self, arg: int, /) -> Symbol: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_symbols: ...

        def __next__(self) -> Symbol: ...

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

    tls: lief.PE.TLS

    rich_header: lief.PE.RichHeader

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

    def predict_function_rva(self, library: str, function: str) -> int: ...

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

    @property
    def codeview_pdb(self) -> CodeViewPDB: ...

    @property
    def load_configuration(self) -> LoadConfiguration: ...

    def get_export(self) -> Export: ...

    @property
    def symbols(self) -> list[Symbol]: ... # type: ignore

    def get_section(self, section_name: str) -> Section: ...

    def add_section(self, section: Section, type: SECTION_TYPES = SECTION_TYPES.UNKNOWN) -> Section: ...

    @property
    def relocations(self) -> Binary.it_relocations: ... # type: ignore

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

    def add_import_function(self, import_name: str, function_name: str) -> ImportEntry: ...

    def add_library(self, import_name: str) -> Import: ...

    def remove_library(self, import_name: str) -> None: ...

    def remove_all_libraries(self) -> None: ...

    def write(self, output_path: str) -> None: ...

    def __str__(self) -> str: ...

class Builder:
    def __init__(self, pe_binary: Binary) -> None: ...

    def build(self) -> Union[lief.ok_t, lief.lief_errors]: ...

    def build_imports(self, enable: bool = True) -> Builder: ...

    def patch_imports(self, enable: bool = True) -> Builder: ...

    def build_relocations(self, enable: bool = True) -> Builder: ...

    def build_tls(self, enable: bool = True) -> Builder: ...

    def build_resources(self, enable: bool = True) -> Builder: ...

    def build_overlay(self, enable: bool = True) -> Builder: ...

    def build_dos_stub(self, enable: bool = True) -> Builder: ...

    def write(self, output: str) -> None: ...

    def get_build(self) -> list[int]: ...

    def __str__(self) -> str: ...

class CODE_PAGES(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> CODE_PAGES: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    IBM037 = 37

    IBM437 = 437

    IBM500 = 500

    ASMO_708 = 708

    DOS_720 = 720

    IBM737 = 737

    IBM775 = 775

    IBM850 = 850

    IBM852 = 852

    IBM855 = 855

    IBM857 = 857

    IBM00858 = 858

    IBM860 = 860

    IBM861 = 861

    DOS_862 = 862

    IBM863 = 863

    IBM864 = 864

    IBM865 = 865

    CP866 = 866

    IBM869 = 869

    IBM870 = 870

    WINDOWS_874 = 874

    CP875 = 875

    SHIFT_JIS = 932

    GB2312 = 936

    KS_C_5601_1987 = 949

    BIG5 = 950

    IBM1026 = 1026

    IBM01047 = 1047

    IBM01140 = 1140

    IBM01141 = 1141

    IBM01142 = 1142

    IBM01143 = 1143

    IBM01144 = 1144

    IBM01145 = 1145

    IBM01146 = 1146

    IBM01147 = 1147

    IBM01148 = 1148

    IBM01149 = 1149

    UTF_16 = 1200

    UNICODEFFFE = 1201

    WINDOWS_1250 = 1250

    WINDOWS_1251 = 1251

    WINDOWS_1252 = 1252

    WINDOWS_1253 = 1253

    WINDOWS_1254 = 1254

    WINDOWS_1255 = 1255

    WINDOWS_1256 = 1256

    WINDOWS_1257 = 1257

    WINDOWS_1258 = 1258

    JOHAB = 1361

    MACINTOSH = 10000

    X_MAC_JAPANESE = 10001

    X_MAC_CHINESETRAD = 10002

    X_MAC_KOREAN = 10003

    X_MAC_ARABIC = 10004

    X_MAC_HEBREW = 10005

    X_MAC_GREEK = 10006

    X_MAC_CYRILLIC = 10007

    X_MAC_CHINESESIMP = 10008

    X_MAC_ROMANIAN = 10010

    X_MAC_UKRAINIAN = 10017

    X_MAC_THAI = 10021

    X_MAC_CE = 10029

    X_MAC_ICELANDIC = 10079

    X_MAC_TURKISH = 10081

    X_MAC_CROATIAN = 10082

    UTF_32 = 12000

    UTF_32BE = 12001

    X_CHINESE_CNS = 20000

    X_CP20001 = 20001

    X_CHINESE_ETEN = 20002

    X_CP20003 = 20003

    X_CP20004 = 20004

    X_CP20005 = 20005

    X_IA5 = 20105

    X_IA5_GERMAN = 20106

    X_IA5_SWEDISH = 20107

    X_IA5_NORWEGIAN = 20108

    US_ASCII = 20127

    X_CP20261 = 20261

    X_CP20269 = 20269

    IBM273 = 20273

    IBM277 = 20277

    IBM278 = 20278

    IBM280 = 20280

    IBM284 = 20284

    IBM285 = 20285

    IBM290 = 20290

    IBM297 = 20297

    IBM420 = 20420

    IBM423 = 20423

    IBM424 = 20424

    X_EBCDIC_KOREANEXTENDED = 20833

    IBM_THAI = 20838

    KOI8_R = 20866

    IBM871 = 20871

    IBM880 = 20880

    IBM905 = 20905

    IBM00924 = 20924

    EUC_JP_JIS = 20932

    X_CP20936 = 20936

    X_CP20949 = 20949

    CP1025 = 21025

    KOI8_U = 21866

    ISO_8859_1 = 28591

    ISO_8859_2 = 28592

    ISO_8859_3 = 28593

    ISO_8859_4 = 28594

    ISO_8859_5 = 28595

    ISO_8859_6 = 28596

    ISO_8859_7 = 28597

    ISO_8859_8 = 28598

    ISO_8859_9 = 28599

    ISO_8859_13 = 28603

    ISO_8859_15 = 28605

    X_EUROPA = 29001

    ISO_8859_8_I = 38598

    ISO_2022_JP = 50220

    CSISO2022JP = 50221

    ISO_2022_JP_JIS = 50222

    ISO_2022_KR = 50225

    X_CP50227 = 50227

    EUC_JP = 51932

    EUC_CN = 51936

    EUC_KR = 51949

    HZ_GB_2312 = 52936

    GB18030 = 54936

    X_ISCII_DE = 57002

    X_ISCII_BE = 57003

    X_ISCII_TA = 57004

    X_ISCII_TE = 57005

    X_ISCII_AS = 57006

    X_ISCII_OR = 57007

    X_ISCII_KA = 57008

    X_ISCII_MA = 57009

    X_ISCII_GU = 57010

    X_ISCII_PA = 57011

    UTF_7 = 65000

    UTF_8 = 65001

class CodeIntegrity(lief.Object):
    def __init__(self) -> None: ...

    flags: int

    catalog: int

    catalog_offset: int

    reserved: int

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
    def __init__(self) -> None: ...

    @property
    def parent(self) -> lief.PE.CodeView: ...

    @property
    def guid(self) -> str: ...

    signature: list[int]

    age: int

    filename: Union[str, bytes]

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

class ContentType(Attribute):
    @property
    def oid(self) -> str: ...

class DIALOG_BOX_STYLES(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> DIALOG_BOX_STYLES: ...

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

    D3DLOOK = 4

    FIXEDSYS = 8

    NOFAILCREATE = 16

    CONTROL = 1024

    CENTER = 2048

    CENTERMOUSE = 4096

    CONTEXTHELP = 8192

    SHELLFONT = 72

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
    def type(self) -> DataDirectory.TYPES: ...

    @property
    def has_section(self) -> bool: ...

    def copy(self) -> DataDirectory: ...

    def __str__(self) -> str: ...

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

        RESERVED = 10

        CLSID = 11

        VC_FEATURE = 12

        POGO = 13

        ILTCG = 14

        MPX = 15

        REPRO = 16

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

    def copy(self) -> Optional[Debug]: ...

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

class EXTENDED_WINDOW_STYLES(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> EXTENDED_WINDOW_STYLES: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    DLGMODALFRAME = 1

    NOPARENTNOTIFY = 4

    TOPMOST = 8

    ACCEPTFILES = 16

    TRANSPARENT = 32

    MDICHILD = 64

    TOOLWINDOW = 128

    WINDOWEDGE = 256

    CLIENTEDGE = 512

    CONTEXTHELP = 1024

    RIGHT = 4096

    LEFT = 0

    RTLREADING = 8192

    LTRREADING = 0

    LEFTSCROLLBAR = 16384

    RIGHTSCROLLBAR = 0

    CONTROLPARENT = 65536

    STATICEDGE = 131072

    APPWINDOW = 262144

class Export(lief.Object):
    def __init__(self) -> None: ...

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

    def copy(self) -> Export: ...

    def __str__(self) -> str: ...

class ExportEntry(lief.Symbol):
    def __init__(self) -> None: ...

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

    def __str__(self) -> str: ...

class FIXED_VERSION_FILE_FLAGS(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> FIXED_VERSION_FILE_FLAGS: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    DEBUG = 1

    INFOINFERRED = 16

    PATCHED = 4

    PRERELEASE = 2

    PRIVATEBUILD = 8

    SPECIALBUILD = 32

class FIXED_VERSION_FILE_SUB_TYPES(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> FIXED_VERSION_FILE_SUB_TYPES: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    DRV_COMM = 10

    DRV_DISPLAY = 4

    DRV_INSTALLABLE = 8

    DRV_KEYBOARD = 2

    DRV_LANGUAGE = 3

    DRV_MOUSE = 5

    DRV_NETWORK = 6

    DRV_PRINTER = 1

    DRV_SOUND = 9

    DRV_SYSTEM = 7

    DRV_VERSIONED_PRINTER = 12

    FONT_RASTER = 1

    FONT_TRUETYPE = 3

    FONT_VECTOR = 2

    UNKNOWN = 0

class FIXED_VERSION_FILE_TYPES(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> FIXED_VERSION_FILE_TYPES: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    APP = 1

    DLL = 2

    DRV = 3

    FONT = 4

    STATIC_LIB = 7

    UNKNOWN = 0

    VXD = 5

class FIXED_VERSION_OS(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> FIXED_VERSION_OS: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    UNKNOWN = 0

    DOS = 65536

    NT = 262144

    WINDOWS16 = 1

    WINDOWS32 = 4

    OS216 = 131072

    OS232 = 196608

    PM16 = 2

    PM32 = 3

    DOS_WINDOWS16 = 65537

    DOS_WINDOWS32 = 65540

    NT_WINDOWS32 = 262148

    OS216_PM16 = 131074

    OS232_PM32 = 196611

class GenericContent(ContentInfo.Content):
    pass

class GenericType(Attribute):
    @property
    def oid(self) -> str: ...

    @property
    def raw_content(self) -> memoryview: ...

class Header(lief.Object):
    class MACHINE_TYPES(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Header.MACHINE_TYPES: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        AM33 = 467

        AMD64 = 34404

        ARM = 448

        ARMNT = 452

        ARM64 = 43620

        EBC = 3772

        I386 = 332

        IA64 = 512

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

    machine: lief.PE.Header.MACHINE_TYPES

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

class IMPHASH_MODE(enum.Enum):
    DEFAULT = 0

    LIEF = 0

    PEFILE = 1

    VT = 1

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

    def __str__(self) -> str: ...

class ImportEntry(lief.Symbol):
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, import_name: str) -> None: ...

    @overload
    def __init__(self, data: int, name: str = '') -> None: ...

    @overload
    def __init__(self, data: int, type: PE_TYPE, name: str = '') -> None: ...

    @overload
    def __init__(self, name: str, type: PE_TYPE) -> None: ...

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
    def iat_address(self) -> int: ...

    def copy(self) -> ImportEntry: ...

    def __str__(self) -> str: ...

class LangCodeItem(lief.Object):
    type: int

    key: str

    lang: int

    sublang: int

    code_page: lief.PE.CODE_PAGES

    items: dict

    def __str__(self) -> str: ...

class LoadConfiguration(lief.Object):
    def __init__(self) -> None: ...

    class VERSION(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> LoadConfiguration.VERSION: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        SEH = 1

        WIN_8_1 = 2

        WIN_10_0_9879 = 3

        WIN_10_0_14286 = 4

        WIN_10_0_14383 = 5

        WIN_10_0_14901 = 6

        WIN_10_0_15002 = 7

        WIN_10_0_16237 = 8

        WIN_10_0_18362 = 9

        WIN_10_0_19534 = 10

        WIN_10_0_MSVC_2019 = 11

        WIN_10_0_MSVC_2019_16 = 12

    @property
    def version(self) -> LoadConfiguration.VERSION: ...

    characteristics: int

    @property
    def size(self) -> int: ...

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

    reserved1: int

    dependent_load_flags: int

    editlist: int

    security_cookie: int

    def copy(self) -> LoadConfiguration: ...

    def __str__(self) -> str: ...

class LoadConfigurationV0(LoadConfiguration):
    def __init__(self) -> None: ...

    se_handler_table: int

    se_handler_count: int

    def copy(self) -> LoadConfigurationV0: ...

    def __str__(self) -> str: ...

class LoadConfigurationV1(LoadConfigurationV0):
    def __init__(self) -> None: ...

    class IMAGE_GUARD(enum.Flag):
        @staticmethod
        def from_value(arg: int, /) -> LoadConfigurationV1.IMAGE_GUARD: ...

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

        EH_CONTINUATION_TABLE_PRESENT = 2097152

    guard_cf_check_function_pointer: int

    guard_cf_dispatch_function_pointer: int

    guard_cf_function_table: int

    guard_cf_function_count: int

    guard_flags: lief.PE.LoadConfigurationV1.IMAGE_GUARD

    def has(self, flag: LoadConfigurationV1.IMAGE_GUARD) -> bool: ...

    @property
    def guard_cf_flags_list(self) -> list[LoadConfigurationV1.IMAGE_GUARD]: ...

    def __contains__(self, arg: LoadConfigurationV1.IMAGE_GUARD, /) -> bool: ...

    def copy(self) -> LoadConfigurationV1: ...

    def __str__(self) -> str: ...

class LoadConfigurationV10(LoadConfigurationV9):
    def __init__(self) -> None: ...

    guard_xfg_check_function_pointer: int

    guard_xfg_dispatch_function_pointer: int

    guard_xfg_table_dispatch_function_pointer: int

    def copy(self) -> LoadConfigurationV10: ...

    def __str__(self) -> str: ...

class LoadConfigurationV11(LoadConfigurationV10):
    def __init__(self) -> None: ...

    cast_guard_os_determined_failure_mode: int

    def copy(self) -> LoadConfigurationV11: ...

    def __str__(self) -> str: ...

class LoadConfigurationV2(LoadConfigurationV1):
    def __init__(self) -> None: ...

    @property
    def code_integrity(self) -> CodeIntegrity: ...

    def copy(self) -> LoadConfigurationV2: ...

    def __str__(self) -> str: ...

class LoadConfigurationV3(LoadConfigurationV2):
    def __init__(self) -> None: ...

    guard_address_taken_iat_entry_table: int

    guard_address_taken_iat_entry_count: int

    guard_long_jump_target_table: int

    guard_long_jump_target_count: int

    def copy(self) -> LoadConfigurationV3: ...

    def __str__(self) -> str: ...

class LoadConfigurationV4(LoadConfigurationV3):
    def __init__(self) -> None: ...

    dynamic_value_reloc_table: int

    hybrid_metadata_pointer: int

    def copy(self) -> LoadConfigurationV4: ...

    def __str__(self) -> str: ...

class LoadConfigurationV5(LoadConfigurationV4):
    def __init__(self) -> None: ...

    guard_rf_failure_routine: int

    guard_rf_failure_routine_function_pointer: int

    dynamic_value_reloctable_offset: int

    dynamic_value_reloctable_section: int

    reserved2: int

    def copy(self) -> LoadConfigurationV5: ...

    def __str__(self) -> str: ...

class LoadConfigurationV6(LoadConfigurationV5):
    def __init__(self) -> None: ...

    guard_rf_verify_stackpointer_function_pointer: int

    hotpatch_table_offset: int

    def copy(self) -> LoadConfigurationV6: ...

    def __str__(self) -> str: ...

class LoadConfigurationV7(LoadConfigurationV6):
    def __init__(self) -> None: ...

    reserved3: int

    addressof_unicode_string: int

    def copy(self) -> LoadConfigurationV7: ...

    def __str__(self) -> str: ...

class LoadConfigurationV8(LoadConfigurationV7):
    def __init__(self) -> None: ...

    volatile_metadata_pointer: int

    def copy(self) -> LoadConfigurationV8: ...

    def __str__(self) -> str: ...

class LoadConfigurationV9(LoadConfigurationV8):
    def __init__(self) -> None: ...

    guard_eh_continuation_table: int

    guard_eh_continuation_count: int

    def copy(self) -> LoadConfigurationV9: ...

    def __str__(self) -> str: ...

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

class MsManifestBinaryID(Attribute):
    manifest_id: str

    def __str__(self) -> str: ...

class MsSpcNestedSignature(Attribute):
    @property
    def signature(self) -> Signature: ...

class MsSpcStatementType(Attribute):
    @property
    def oid(self) -> str: ...

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

    magic: lief.PE.PE_TYPE

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

    subsystem: lief.PE.OptionalHeader.SUBSYSTEM

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

class PE_TYPE(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> PE_TYPE: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    PE32 = 267

    PE32_PLUS = 523

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

class PKCS9TSTInfo(ContentInfo.Content):
    pass

class ParserConfig:
    def __init__(self) -> None: ...

    parse_signature: bool

    parse_exports: bool

    parse_imports: bool

    parse_rsrc: bool

    parse_reloc: bool

    all: lief.PE.ParserConfig = ...

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
    def __init__(self) -> None: ...

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

        MIPS_JMPADDR = 5

        ARM_MOV32A = 262

        ARM_MOV32 = 263

        RISCV_HI20 = 264

        SECTION = 6

        REL = 7

        ARM_MOV32T = 520

        THUMB_MOV32 = 521

        RISCV_LOW12I = 522

        RISCV_LOW12S = 8

        MIPS_JMPADDR16 = 777

        IA64_IMM64 = 9

        DIR64 = 10

        HIGH3ADJ = 11

    data: int

    position: int

    type: lief.PE.RelocationEntry.BASE_TYPES

    def __str__(self) -> str: ...

class Repro(Debug):
    hash: memoryview

    def __str__(self) -> str: ...

class ResourceAccelerator(lief.Object):
    @property
    def flags(self) -> int: ...

    @property
    def ansi(self) -> int: ...

    @property
    def id(self) -> int: ...

    @property
    def padding(self) -> int: ...

    def __str__(self) -> str: ...

class ResourceData(ResourceNode):
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, content: Sequence[int], code_page: int) -> None: ...

    code_page: int

    content: memoryview

    reserved: int

    @property
    def offset(self) -> int: ...

    def __str__(self) -> str: ...

class ResourceDialog(lief.Object):
    class it_const_items:
        def __getitem__(self, arg: int, /) -> ResourceDialogItem: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> ResourceDialog.it_const_items: ...

        def __next__(self) -> ResourceDialogItem: ...

    @property
    def is_extended(self) -> bool: ...

    @property
    def version(self) -> int: ...

    @property
    def signature(self) -> int: ...

    @property
    def help_id(self) -> int: ...

    @property
    def x(self) -> int: ...

    @property
    def y(self) -> int: ...

    @property
    def cx(self) -> int: ...

    @property
    def cy(self) -> int: ...

    @property
    def title(self) -> str: ...

    @property
    def typeface(self) -> str: ...

    @property
    def weight(self) -> int: ...

    @property
    def point_size(self) -> int: ...

    @property
    def charset(self) -> int: ...

    @property
    def style_list(self) -> set[WINDOW_STYLES]: ...

    @property
    def dialogbox_style_list(self) -> set[DIALOG_BOX_STYLES]: ...

    @property
    def extended_style_list(self) -> set[DIALOG_BOX_STYLES]: ...

    @property
    def style(self) -> int: ...

    @property
    def extended_style(self) -> int: ...

    @property
    def items(self) -> ResourceDialog.it_const_items: ...

    def has_style(self, style: WINDOW_STYLES) -> bool: ...

    def has_dialogbox_style(self, style: DIALOG_BOX_STYLES) -> bool: ...

    def has_extended_style(self, style: EXTENDED_WINDOW_STYLES) -> bool: ...

    lang: int

    sub_lang: int

    def __str__(self) -> str: ...

class ResourceDialogItem(lief.Object):
    @property
    def is_extended(self) -> bool: ...

    @property
    def help_id(self) -> int: ...

    @property
    def extended_style(self) -> int: ...

    @property
    def style(self) -> int: ...

    @property
    def x(self) -> int: ...

    @property
    def y(self) -> int: ...

    @property
    def cx(self) -> int: ...

    @property
    def cy(self) -> int: ...

    @property
    def id(self) -> int: ...

    @property
    def title(self) -> str: ...

    def __str__(self) -> str: ...

class ResourceDirectory(ResourceNode):
    def __init__(self) -> None: ...

    characteristics: int

    time_date_stamp: int

    major_version: int

    minor_version: int

    numberof_name_entries: int

    numberof_id_entries: int

    def __str__(self) -> str: ...

class ResourceFixedFileInfo(lief.Object):
    signature: int

    struct_version: int

    file_version_MS: int

    file_version_LS: int

    product_version_MS: int

    product_version_LS: int

    file_flags_mask: int

    file_flags: int

    file_os: lief.PE.FIXED_VERSION_OS

    file_type: lief.PE.FIXED_VERSION_FILE_TYPES

    file_subtype: lief.PE.FIXED_VERSION_FILE_SUB_TYPES

    file_date_MS: int

    file_date_LS: int

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

    def __str__(self) -> str: ...

class ResourceNode(lief.Object):
    class it_childs:
        def __getitem__(self, arg: int, /) -> ResourceNode: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> ResourceNode.it_childs: ...

        def __next__(self) -> ResourceNode: ...

    id: int

    @property
    def is_directory(self) -> bool: ...

    @property
    def is_data(self) -> bool: ...

    @property
    def has_name(self) -> bool: ...

    name: Union[str, bytes]

    @property
    def childs(self) -> ResourceNode.it_childs: ...

    def add_directory_node(self, resource_directory: ResourceDirectory) -> ResourceNode: ...

    def add_data_node(self, resource_data: ResourceData) -> ResourceNode: ...

    @overload
    def delete_child(self, node: ResourceNode) -> None: ...

    @overload
    def delete_child(self, id: int) -> None: ...

    @property
    def depth(self) -> int: ...

    def copy(self) -> Optional[ResourceNode]: ...

    def __str__(self) -> str: ...

class ResourceStringFileInfo(lief.Object):
    type: int

    key: str

    langcode_items: list[lief.PE.LangCodeItem]

    def __str__(self) -> str: ...

class ResourceStringTable(lief.Object):
    @property
    def length(self) -> int: ...

    @property
    def name(self) -> str: ...

    def __str__(self) -> str: ...

class ResourceVarFileInfo(lief.Object):
    type: int

    key: str

    translations: list[int]

    def __str__(self) -> str: ...

class ResourceVersion(lief.Object):
    type: int

    key: str

    fixed_file_info: lief.PE.ResourceFixedFileInfo

    string_file_info: lief.PE.ResourceStringFileInfo

    var_file_info: lief.PE.ResourceVarFileInfo

    @property
    def has_fixed_file_info(self) -> bool: ...

    @property
    def has_string_file_info(self) -> bool: ...

    @property
    def has_var_file_info(self) -> bool: ...

    def remove_fixed_file_info(self) -> None: ...

    def remove_string_file_info(self) -> None: ...

    def remove_var_file_info(self) -> None: ...

    def __str__(self) -> str: ...

class ResourcesManager(lief.Object):
    def __init__(self, arg: ResourceNode, /) -> None: ...

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

    class it_const_strings_table:
        def __getitem__(self, arg: int, /) -> ResourceStringTable: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> ResourcesManager.it_const_strings_table: ...

        def __next__(self) -> ResourceStringTable: ...

    class it_const_accelerators:
        def __getitem__(self, arg: int, /) -> ResourceAccelerator: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> ResourcesManager.it_const_accelerators: ...

        def __next__(self) -> ResourceAccelerator: ...

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
    def version(self) -> Union[ResourceVersion, lief.lief_errors]: ...

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
    def string_table(self) -> ResourcesManager.it_const_strings_table: ...

    @property
    def has_html(self) -> bool: ...

    @property
    def html(self) -> list[str]: ...

    @property
    def has_accelerator(self) -> bool: ...

    @property
    def accelerator(self) -> ResourcesManager.it_const_accelerators: ...

    def get_node_type(self, type: ResourcesManager.TYPE) -> ResourceNode: ...

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

class SECTION_TYPES(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> SECTION_TYPES: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    TEXT = 0

    IDATA = 2

    DATA = 3

    BSS = 4

    RESOURCE = 5

    RELOCATION = 6

    EXPORT = 7

    UNKNOWN = 10

class SYMBOL_BASE_TYPES(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> SYMBOL_BASE_TYPES: ...

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

class SYMBOL_COMPLEX_TYPES(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> SYMBOL_COMPLEX_TYPES: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    NULL = 0

    POINTER = 1

    FUNCTION = 2

    ARRAY = 3

    COMPLEX_TYPE_SHIFT = 4

class SYMBOL_SECTION_NUMBER(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> SYMBOL_SECTION_NUMBER: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    DEBUG = -2

    ABSOLUTE = -1

    UNDEFINED = 0

class SYMBOL_STORAGE_CLASS(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> SYMBOL_STORAGE_CLASS: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    END_OF_FUNCTION = -1

    NULL = 0

    AUTOMATIC = 1

    EXTERNAL = 2

    STATIC = 3

    REGISTER = 4

    EXTERNAL_DEF = 5

    LABEL = 6

    UNDEFINED_LABEL = 7

    MEMBER_OF_STRUCT = 8

    UNION_TAG = 12

    TYPE_DEFINITION = 13

    UDEFINED_STATIC = 14

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

class Section(lief.Section):
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, content: Sequence[int], name: str = '', characteristics: int = 0) -> None: ...

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
    def padding(self) -> bytes: ...

    def copy(self) -> Section: ...

    def __str__(self) -> str: ...

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
    def parse(path: str) -> Optional[Signature]: ...

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

class SigningCertificateV2(Attribute):
    pass

class SpcIndirectData(ContentInfo.Content):
    @property
    def digest_algorithm(self) -> ALGORITHMS: ...

    @property
    def digest(self) -> memoryview: ...

    @property
    def file(self) -> str: ...

    def __str__(self) -> str: ...

class SpcRelaxedPeMarkerCheck(Attribute):
    @property
    def value(self) -> int: ...

class SpcSpOpusInfo(Attribute):
    @property
    def program_name(self) -> Union[str, bytes]: ...

    @property
    def more_info(self) -> Union[str, bytes]: ...

class Symbol(lief.Symbol):
    def __init__(self) -> None: ...

    name: Union[str, bytes]

    @property
    def section_number(self) -> int: ...

    @property
    def type(self) -> int: ...

    @property
    def base_type(self) -> SYMBOL_BASE_TYPES: ...

    @property
    def complex_type(self) -> SYMBOL_COMPLEX_TYPES: ...

    @property
    def storage_class(self) -> SYMBOL_STORAGE_CLASS: ...

    @property
    def numberof_aux_symbols(self) -> int: ...

    @property
    def section(self) -> Section: ...

    @property
    def has_section(self) -> bool: ...

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

    def copy(self) -> TLS: ...

    def __str__(self) -> str: ...

class WINDOW_STYLES(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> WINDOW_STYLES: ...

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

    MINIMIZEBOX = 131072

    MAXIMIZEBOX = 65536

def get_imphash(binary: Binary, mode: IMPHASH_MODE = IMPHASH_MODE.DEFAULT) -> str: ...

@overload
def get_type(file: str) -> Union[PE_TYPE, lief.lief_errors]: ...

@overload
def get_type(raw: Sequence[int]) -> Union[PE_TYPE, lief.lief_errors]: ...

def oid_to_string(arg: str, /) -> str: ...

@overload
def parse(filename: str, config: ParserConfig = ...) -> Optional[Binary]: ...

@overload
def parse(raw: Sequence[int], config: ParserConfig = ...) -> Optional[Binary]: ...

@overload
def parse(obj: Union[io.IOBase | os.PathLike], config: ParserConfig = ...) -> Optional[Binary]: ...

def resolve_ordinals(imp: Import, strict: bool = False, use_std: bool = False) -> Union[Import, lief.lief_errors]: ...

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
