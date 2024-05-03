/* Copyright 2021 - 2024 R. Thomas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef LIEF_PE_ENUMS_H
#define LIEF_PE_ENUMS_H
#include <cinttypes>
#include <cstddef>
#include "LIEF/enums.hpp"
#define LIEF_PE_FORCE_UNDEF
#include "LIEF/PE/undef.h"

namespace LIEF {
namespace PE {

enum class PE_TYPES: size_t  {
    PE32      = 0x10b, /** 32bits  */
    PE32_PLUS = 0x20b  /** 64 bits */
};


enum SYMBOL_SECTION_NUMBER: int {
  IMAGE_SYM_DEBUG     = -2,
  IMAGE_SYM_ABSOLUTE  = -1,
  IMAGE_SYM_UNDEFINED = 0
};

/// Storage class tells where and what the symbol represents
enum SYMBOL_STORAGE_CLASS: int {
  IMAGE_SYM_CLASS_INVALID = 0xFF,

  IMAGE_SYM_CLASS_END_OF_FUNCTION  = -1,  ///< Physical end of function
  IMAGE_SYM_CLASS_NULL             = 0,   ///< No symbol
  IMAGE_SYM_CLASS_AUTOMATIC        = 1,   ///< Stack variable
  IMAGE_SYM_CLASS_EXTERNAL         = 2,   ///< External symbol
  IMAGE_SYM_CLASS_STATIC           = 3,   ///< Static
  IMAGE_SYM_CLASS_REGISTER         = 4,   ///< Register variable
  IMAGE_SYM_CLASS_EXTERNAL_DEF     = 5,   ///< External definition
  IMAGE_SYM_CLASS_LABEL            = 6,   ///< Label
  IMAGE_SYM_CLASS_UNDEFINED_LABEL  = 7,   ///< Undefined label
  IMAGE_SYM_CLASS_MEMBER_OF_STRUCT = 8,   ///< Member of structure
  IMAGE_SYM_CLASS_ARGUMENT         = 9,   ///< Function argument
  IMAGE_SYM_CLASS_STRUCT_TAG       = 10,  ///< Structure tag
  IMAGE_SYM_CLASS_MEMBER_OF_UNION  = 11,  ///< Member of union
  IMAGE_SYM_CLASS_UNION_TAG        = 12,  ///< Union tag
  IMAGE_SYM_CLASS_TYPE_DEFINITION  = 13,  ///< Type definition
  IMAGE_SYM_CLASS_UNDEFINED_STATIC = 14,  ///< Undefined static
  IMAGE_SYM_CLASS_ENUM_TAG         = 15,  ///< Enumeration tag
  IMAGE_SYM_CLASS_MEMBER_OF_ENUM   = 16,  ///< Member of enumeration
  IMAGE_SYM_CLASS_REGISTER_PARAM   = 17,  ///< Register parameter
  IMAGE_SYM_CLASS_BIT_FIELD        = 18,  ///< Bit field ".bb" or ".eb" - beginning or end of block
  IMAGE_SYM_CLASS_BLOCK            = 100, ///< ".bf" or ".ef" - beginning or end of function
  IMAGE_SYM_CLASS_FUNCTION         = 101,
  IMAGE_SYM_CLASS_END_OF_STRUCT    = 102, ///< End of structure
  IMAGE_SYM_CLASS_FILE             = 103, ///< File name line number, reformatted as symbol
  IMAGE_SYM_CLASS_SECTION          = 104,
  IMAGE_SYM_CLASS_WEAK_EXTERNAL    = 105, ///< Duplicate tag external symbol in dmert public lib
  IMAGE_SYM_CLASS_CLR_TOKEN        = 107
};


enum class SYMBOL_BASE_TYPES: size_t  {
  IMAGE_SYM_TYPE_NULL   = 0,  ///< No type information or unknown base type.
  IMAGE_SYM_TYPE_VOID   = 1,  ///< Used with void pointers and functions.
  IMAGE_SYM_TYPE_CHAR   = 2,  ///< A character (signed byte).
  IMAGE_SYM_TYPE_SHORT  = 3,  ///< A 2-byte signed integer.
  IMAGE_SYM_TYPE_INT    = 4,  ///< A natural integer type on the target.
  IMAGE_SYM_TYPE_LONG   = 5,  ///< A 4-byte signed integer.
  IMAGE_SYM_TYPE_FLOAT  = 6,  ///< A 4-byte floating-point number.
  IMAGE_SYM_TYPE_DOUBLE = 7,  ///< An 8-byte floating-point number.
  IMAGE_SYM_TYPE_STRUCT = 8,  ///< A structure.
  IMAGE_SYM_TYPE_UNION  = 9,  ///< An union.
  IMAGE_SYM_TYPE_ENUM   = 10, ///< An enumerated type.
  IMAGE_SYM_TYPE_MOE    = 11, ///< A member of enumeration (a specific value).
  IMAGE_SYM_TYPE_BYTE   = 12, ///< A byte; unsigned 1-byte integer.
  IMAGE_SYM_TYPE_WORD   = 13, ///< A word; unsigned 2-byte integer.
  IMAGE_SYM_TYPE_UINT   = 14, ///< An unsigned integer of natural size.
  IMAGE_SYM_TYPE_DWORD  = 15  ///< An unsigned 4-byte integer.
};

enum class SYMBOL_COMPLEX_TYPES: size_t  {
  IMAGE_SYM_DTYPE_NULL     = 0, ///< No complex type; simple scalar variable.
  IMAGE_SYM_DTYPE_POINTER  = 1, ///< A pointer to base type.
  IMAGE_SYM_DTYPE_FUNCTION = 2, ///< A function that returns a base type.
  IMAGE_SYM_DTYPE_ARRAY    = 3, ///< An array of base type.
  SCT_COMPLEX_TYPE_SHIFT   = 4  ///< Type is formed as (base + (derived << SCT_COMPLEX_TYPE_SHIFT))
};

enum class AuxSymbolType: size_t  {
  IMAGE_AUX_SYMBOL_TYPE_TOKEN_DEF = 1
};


enum class RELOCATIONS_I386: size_t  {
  IMAGE_REL_I386_ABSOLUTE = 0x0000,
  IMAGE_REL_I386_DIR16    = 0x0001,
  IMAGE_REL_I386_REL16    = 0x0002,
  IMAGE_REL_I386_DIR32    = 0x0006,
  IMAGE_REL_I386_DIR32NB  = 0x0007,
  IMAGE_REL_I386_SEG12    = 0x0009,
  IMAGE_REL_I386_SECTION  = 0x000A,
  IMAGE_REL_I386_SECREL   = 0x000B,
  IMAGE_REL_I386_TOKEN    = 0x000C,
  IMAGE_REL_I386_SECREL7  = 0x000D,
  IMAGE_REL_I386_REL32    = 0x0014
};

enum class RELOCATIONS_AMD64: size_t  {
  IMAGE_REL_AMD64_ABSOLUTE = 0x0000,
  IMAGE_REL_AMD64_ADDR64   = 0x0001,
  IMAGE_REL_AMD64_ADDR32   = 0x0002,
  IMAGE_REL_AMD64_ADDR32NB = 0x0003,
  IMAGE_REL_AMD64_REL32    = 0x0004,
  IMAGE_REL_AMD64_REL32_1  = 0x0005,
  IMAGE_REL_AMD64_REL32_2  = 0x0006,
  IMAGE_REL_AMD64_REL32_3  = 0x0007,
  IMAGE_REL_AMD64_REL32_4  = 0x0008,
  IMAGE_REL_AMD64_REL32_5  = 0x0009,
  IMAGE_REL_AMD64_SECTION  = 0x000A,
  IMAGE_REL_AMD64_SECREL   = 0x000B,
  IMAGE_REL_AMD64_SECREL7  = 0x000C,
  IMAGE_REL_AMD64_TOKEN    = 0x000D,
  IMAGE_REL_AMD64_SREL32   = 0x000E,
  IMAGE_REL_AMD64_PAIR     = 0x000F,
  IMAGE_REL_AMD64_SSPAN32  = 0x0010
};

enum class RELOCATIONS_ARM: size_t  {
  IMAGE_REL_ARM_ABSOLUTE  = 0x0000,
  IMAGE_REL_ARM_ADDR32    = 0x0001,
  IMAGE_REL_ARM_ADDR32NB  = 0x0002,
  IMAGE_REL_ARM_BRANCH24  = 0x0003,
  IMAGE_REL_ARM_BRANCH11  = 0x0004,
  IMAGE_REL_ARM_TOKEN     = 0x0005,
  IMAGE_REL_ARM_BLX24     = 0x0008,
  IMAGE_REL_ARM_BLX11     = 0x0009,
  IMAGE_REL_ARM_SECTION   = 0x000E,
  IMAGE_REL_ARM_SECREL    = 0x000F,
  IMAGE_REL_ARM_MOV32A    = 0x0010,
  IMAGE_REL_ARM_MOV32T    = 0x0011,
  IMAGE_REL_ARM_BRANCH20T = 0x0012,
  IMAGE_REL_ARM_BRANCH24T = 0x0014,
  IMAGE_REL_ARM_BLX23T    = 0x0015
};


/// These are not documented in the spec, but are located in WinNT.h.
enum class WeakExternalCharacteristics: size_t  {
  IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY = 1,
  IMAGE_WEAK_EXTERN_SEARCH_LIBRARY   = 2,
  IMAGE_WEAK_EXTERN_SEARCH_ALIAS     = 3
};


enum class ImportType: size_t  {
  IMPORT_CODE  = 0,
  IMPORT_DATA  = 1,
  IMPORT_CONST = 2
};


enum class ImportNameType: size_t  {
  /// Import is by ordinal. This indicates that the value in the Ordinal/Hint
  /// field of the import header is the import's ordinal. If this constant is
  /// not specified, then the Ordinal/Hint field should always be interpreted
  /// as the import's hint.
  IMPORT_ORDINAL         = 0,
  /// The import name is identical to the public symbol name
  IMPORT_NAME            = 1,
  /// The import name is the public symbol name, but skipping the leading ?,
  /// @, or optionally _.
  IMPORT_NAME_NOPREFIX   = 2,
  /// The import name is the public symbol name, but skipping the leading ?,
  /// @, or optionally _, and truncating at the first @.
  IMPORT_NAME_UNDECORATE = 3
};


enum class CodeViewIdentifiers: size_t  {
  DEBUG_LINE_TABLES_HAVE_COLUMN_RECORDS = 0x1,
  DEBUG_SECTION_MAGIC = 0x4,
  DEBUG_SYMBOL_SUBSECTION = 0xF1,
  DEBUG_LINE_TABLE_SUBSECTION = 0xF2,
  DEBUG_STRING_TABLE_SUBSECTION = 0xF3,
  DEBUG_INDEX_SUBSECTION = 0xF4,

  // Symbol subsections are split into records of different types.
  DEBUG_SYMBOL_TYPE_PROC_START = 0x1147,
  DEBUG_SYMBOL_TYPE_PROC_END = 0x114F
};


//! From https://docs.microsoft.com/en-us/windows/win32/winmsg/extended-window-styles
enum class EXTENDED_WINDOW_STYLES: size_t  {
  WS_EX_DLGMODALFRAME    = 0x00000001L,
  WS_EX_NOPARENTNOTIFY   = 0x00000004L,
  WS_EX_TOPMOST          = 0x00000008L,
  WS_EX_ACCEPTFILES      = 0x00000010L,
  WS_EX_TRANSPARENT      = 0x00000020L,
  WS_EX_MDICHILD         = 0x00000040L,
  WS_EX_TOOLWINDOW       = 0x00000080L,
  WS_EX_WINDOWEDGE       = 0x00000100L,
  WS_EX_CLIENTEDGE       = 0x00000200L,
  WS_EX_CONTEXTHELP      = 0x00000400L,

  WS_EX_RIGHT            = 0x00001000L,
  WS_EX_LEFT             = 0x00000000L,
  WS_EX_RTLREADING       = 0x00002000L,
  WS_EX_LTRREADING       = 0x00000000L,
  WS_EX_LEFTSCROLLBAR    = 0x00004000L,
  WS_EX_RIGHTSCROLLBAR   = 0x00000000L,

  WS_EX_CONTROLPARENT    = 0x00010000L,
  WS_EX_STATICEDGE       = 0x00020000L,
  WS_EX_APPWINDOW        = 0x00040000L,
};

//! From: https://docs.microsoft.com/en-us/windows/win32/winmsg/window-styles
enum class WINDOW_STYLES: size_t  {
  WS_OVERLAPPED      = 0x00000000L,
  WS_POPUP           = 0x80000000L,
  WS_CHILD           = 0x40000000L,
  WS_MINIMIZE        = 0x20000000L,
  WS_VISIBLE         = 0x10000000L,
  WS_DISABLED        = 0x08000000L,
  WS_CLIPSIBLINGS    = 0x04000000L,
  WS_CLIPCHILDREN    = 0x02000000L,
  WS_MAXIMIZE        = 0x01000000L,
  WS_CAPTION         = 0x00C00000L,
  WS_BORDER          = 0x00800000L,
  WS_DLGFRAME        = 0x00400000L,
  WS_VSCROLL         = 0x00200000L,
  WS_HSCROLL         = 0x00100000L,
  WS_SYSMENU         = 0x00080000L,
  WS_THICKFRAME      = 0x00040000L,
  WS_GROUP           = 0x00020000L,
  WS_TABSTOP         = 0x00010000L,

  WS_MINIMIZEBOX     = 0x00020000L,
  WS_MAXIMIZEBOX     = 0x00010000L,
};


//! From https://docs.microsoft.com/en-us/windows/win32/dlgbox/dialog-box-styles
enum class DIALOG_BOX_STYLES: size_t  {
  DS_ABSALIGN      = 0x0001L,
  DS_SYSMODAL      = 0x0002L,
  DS_LOCALEDIT     = 0x0020L,
  DS_SETFONT       = 0x0040L,
  DS_MODALFRAME    = 0x0080L,
  DS_NOIDLEMSG     = 0x0100L,
  DS_SETFOREGROUND = 0x0200L,
  DS_3DLOOK        = 0x0004L,
  DS_FIXEDSYS      = 0x0008L,
  DS_NOFAILCREATE  = 0x0010L,
  DS_CONTROL       = 0x0400L,
  DS_CENTER        = 0x0800L,
  DS_CENTERMOUSE   = 0x1000L,
  DS_CONTEXTHELP   = 0x2000L,
  DS_SHELLFONT     = 0x0040L | 0x0008L, // DS_SETFONT | DS_FIXEDSYS
};

enum class FIXED_VERSION_OS: size_t  {
  VOS_UNKNOWN       = 0x00000000L,
  VOS_DOS           = 0x00010000L,
  VOS_NT            = 0x00040000L,
  VOS__WINDOWS16    = 0x00000001L,
  VOS__WINDOWS32    = 0x00000004L,
  VOS_OS216         = 0x00020000L,
  VOS_OS232         = 0x00030000L,
  VOS__PM16         = 0x00000002L,
  VOS__PM32         = 0x00000003L,
  VOS_DOS_WINDOWS16 = 0x00010000L | 0x00000001L, // VOS_DOS   | VOS__WINDOWS16
  VOS_DOS_WINDOWS32 = 0x00010000L | 0x00000004L, // VOS_DOS   | VOS__WINDOWS32
  VOS_NT_WINDOWS32  = 0x00040000L | 0x00000004L, // VOS_NT    | VOS__WINDOWS32
  VOS_OS216_PM16    = 0x00020000L | 0x00000002L, // VOS_OS216 | VOS__PM16
  VOS_OS232_PM32    = 0x00030000L | 0x00000003L, // VOS_OS232 | VOS__PM32
};


enum class FIXED_VERSION_FILE_FLAGS: size_t  {
  VS_FF_DEBUG        = 0x00000001L,
  VS_FF_INFOINFERRED = 0x00000010L,
  VS_FF_PATCHED      = 0x00000004L,
  VS_FF_PRERELEASE   = 0x00000002L,
  VS_FF_PRIVATEBUILD = 0x00000008L,
  VS_FF_SPECIALBUILD = 0x00000020L,
};


enum class FIXED_VERSION_FILE_TYPES: size_t  {
  VFT_APP        = 0x00000001L,
  VFT_DLL        = 0x00000002L,
  VFT_DRV        = 0x00000003L,
  VFT_FONT       = 0x00000004L,
  VFT_STATIC_LIB = 0x00000007L,
  VFT_UNKNOWN    = 0x00000000L,
  VFT_VXD        = 0x00000005L,
};


enum class FIXED_VERSION_FILE_SUB_TYPES: size_t  {
  VFT2_DRV_COMM              = 0x0000000AL,
  VFT2_DRV_DISPLAY           = 0x00000004L,
  VFT2_DRV_INSTALLABLE       = 0x00000008L,
  VFT2_DRV_KEYBOARD          = 0x00000002L,
  VFT2_DRV_LANGUAGE          = 0x00000003L,
  VFT2_DRV_MOUSE             = 0x00000005L,
  VFT2_DRV_NETWORK           = 0x00000006L,
  VFT2_DRV_PRINTER           = 0x00000001L,
  VFT2_DRV_SOUND             = 0x00000009L,
  VFT2_DRV_SYSTEM            = 0x00000007L,
  VFT2_DRV_VERSIONED_PRINTER = 0x0000000CL,

  VFT2_FONT_RASTER           = 0x00000001L,
  VFT2_FONT_TRUETYPE         = 0x00000003L,
  VFT2_FONT_VECTOR           = 0x00000002L,

  VFT2_UNKNOWN               = 0x00000000L,
};

//! Code page from https://docs.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
enum class CODE_PAGES: size_t  {
  CP_IBM037                  = 37,    /**< IBM EBCDIC US-Canada */
  CP_IBM437                  = 437,   /**< OEM United States */
  CP_IBM500                  = 500,   /**< IBM EBCDIC International */
  CP_ASMO_708                = 708,   /**< Arabic (ASMO 708) */
  CP_DOS_720                 = 720,   /**< Arabic (Transparent ASMO); Arabic (DOS) */
  CP_IBM737                  = 737,   /**< OEM Greek (formerly 437G); Greek (DOS) */
  CP_IBM775                  = 775,   /**< OEM Baltic; Baltic (DOS) */
  CP_IBM850                  = 850,   /**< OEM Multilingual Latin 1; Western European (DOS) */
  CP_IBM852                  = 852,   /**< OEM Latin 2; Central European (DOS) */
  CP_IBM855                  = 855,   /**< OEM Cyrillic (primarily Russian) */
  CP_IBM857                  = 857,   /**< OEM Turkish; Turkish (DOS) */
  CP_IBM00858                = 858,   /**< OEM Multilingual Latin 1 + Euro symbol */
  CP_IBM860                  = 860,   /**< OEM Portuguese; Portuguese (DOS) */
  CP_IBM861                  = 861,   /**< OEM Icelandic; Icelandic (DOS) */
  CP_DOS_862                 = 862,   /**< OEM Hebrew; Hebrew (DOS) */
  CP_IBM863                  = 863,   /**< OEM French Canadian; French Canadian (DOS) */
  CP_IBM864                  = 864,   /**< OEM Arabic; Arabic (864) */
  CP_IBM865                  = 865,   /**< OEM Nordic; Nordic (DOS) */
  CP_CP866                   = 866,   /**< OEM Russian; Cyrillic (DOS) */
  CP_IBM869                  = 869,   /**< OEM Modern Greek; Greek, Modern (DOS) */
  CP_IBM870                  = 870,   /**< IBM EBCDIC Multilingual/ROECE (Latin 2); IBM EBCDIC Multilingual Latin 2 */
  CP_WINDOWS_874             = 874,   /**< ANSI/OEM Thai (same as 28605, ISO 8859-15); Thai (Windows) */
  CP_CP875                   = 875,   /**< IBM EBCDIC Greek Modern */
  CP_SHIFT_JIS               = 932,   /**< ANSI/OEM Japanese; Japanese (Shift-JIS) */
  CP_GB2312                  = 936,   /**< ANSI/OEM Simplified Chinese (PRC, Singapore); Chinese Simplified (GB2312) */
  CP_KS_C_5601_1987          = 949,   /**< ANSI/OEM Korean (Unified Hangul Code) */
  CP_BIG5                    = 950,   /**< ANSI/OEM Traditional Chinese (Taiwan; Hong Kong SAR, PRC); Chinese Traditional (Big5) */
  CP_IBM1026                 = 1026,  /**< IBM EBCDIC Turkish (Latin 5) */
  CP_IBM01047                = 1047,  /**< IBM EBCDIC Latin 1/Open System */
  CP_IBM01140                = 1140,  /**< IBM EBCDIC US-Canada (037 + Euro symbol); IBM EBCDIC (US-Canada-Euro) */
  CP_IBM01141                = 1141,  /**< IBM EBCDIC Germany (20273 + Euro symbol); IBM EBCDIC (Germany-Euro) */
  CP_IBM01142                = 1142,  /**< IBM EBCDIC Denmark-Norway (20277 + Euro symbol); IBM EBCDIC (Denmark-Norway-Euro) */
  CP_IBM01143                = 1143,  /**< IBM EBCDIC Finland-Sweden (20278 + Euro symbol); IBM EBCDIC (Finland-Sweden-Euro) */
  CP_IBM01144                = 1144,  /**< IBM EBCDIC Italy (20280 + Euro symbol); IBM EBCDIC (Italy-Euro) */
  CP_IBM01145                = 1145,  /**< IBM EBCDIC Latin America-Spain (20284 + Euro symbol); IBM EBCDIC (Spain-Euro) */
  CP_IBM01146                = 1146,  /**< IBM EBCDIC United Kingdom (20285 + Euro symbol); IBM EBCDIC (UK-Euro) */
  CP_IBM01147                = 1147,  /**< IBM EBCDIC France (20297 + Euro symbol); IBM EBCDIC (France-Euro) */
  CP_IBM01148                = 1148,  /**< IBM EBCDIC International (500 + Euro symbol); IBM EBCDIC (International-Euro) */
  CP_IBM01149                = 1149,  /**< IBM EBCDIC Icelandic (20871 + Euro symbol); IBM EBCDIC (Icelandic-Euro) */
  CP_UTF_16                  = 1200,  /**< Unicode UTF-16, little endian byte order (BMP of ISO 10646); available only to managed applications */
  CP_UNICODEFFFE             = 1201,  /**< Unicode UTF-16, big endian byte order; available only to managed applications */
  CP_WINDOWS_1250            = 1250,  /**< ANSI Central European; Central European (Windows) */
  CP_WINDOWS_1251            = 1251,  /**< ANSI Cyrillic; Cyrillic (Windows) */
  CP_WINDOWS_1252            = 1252,  /**< ANSI Latin 1; Western European (Windows) */
  CP_WINDOWS_1253            = 1253,  /**< ANSI Greek; Greek (Windows) */
  CP_WINDOWS_1254            = 1254,  /**< ANSI Turkish; Turkish (Windows) */
  CP_WINDOWS_1255            = 1255,  /**< ANSI Hebrew; Hebrew (Windows) */
  CP_WINDOWS_1256            = 1256,  /**< ANSI Arabic; Arabic (Windows) */
  CP_WINDOWS_1257            = 1257,  /**< ANSI Baltic; Baltic (Windows) */
  CP_WINDOWS_1258            = 1258,  /**< ANSI/OEM Vietnamese; Vietnamese (Windows) */
  CP_JOHAB                   = 1361,  /**< Korean (Johab) */
  CP_MACINTOSH               = 10000, /**< MAC Roman; Western European (Mac) */
  CP_X_MAC_JAPANESE          = 10001, /**< Japanese (Mac) */
  CP_X_MAC_CHINESETRAD       = 10002, /**< MAC Traditional Chinese (Big5); Chinese Traditional (Mac) */
  CP_X_MAC_KOREAN            = 10003, /**< Korean (Mac) */
  CP_X_MAC_ARABIC            = 10004, /**< Arabic (Mac) */
  CP_X_MAC_HEBREW            = 10005, /**< Hebrew (Mac) */
  CP_X_MAC_GREEK             = 10006, /**< Greek (Mac) */
  CP_X_MAC_CYRILLIC          = 10007, /**< Cyrillic (Mac) */
  CP_X_MAC_CHINESESIMP       = 10008, /**< MAC Simplified Chinese (GB 2312); Chinese Simplified (Mac) */
  CP_X_MAC_ROMANIAN          = 10010, /**< Romanian (Mac) */
  CP_X_MAC_UKRAINIAN         = 10017, /**< Ukrainian (Mac) */
  CP_X_MAC_THAI              = 10021, /**< Thai (Mac) */
  CP_X_MAC_CE                = 10029, /**< MAC Latin 2; Central European (Mac) */
  CP_X_MAC_ICELANDIC         = 10079, /**< Icelandic (Mac) */
  CP_X_MAC_TURKISH           = 10081, /**< Turkish (Mac) */
  CP_X_MAC_CROATIAN          = 10082, /**< Croatian (Mac) */
  CP_UTF_32                  = 12000, /**< Unicode UTF-32, little endian byte order; available only to managed applications */
  CP_UTF_32BE                = 12001, /**< Unicode UTF-32, big endian byte order; available only to managed applications */
  CP_X_CHINESE_CNS           = 20000, /**< CNS Taiwan; Chinese Traditional (CNS) */
  CP_X_CP20001               = 20001, /**< TCA Taiwan */
  CP_X_CHINESE_ETEN          = 20002, /**< Eten Taiwan; Chinese Traditional (Eten) */
  CP_X_CP20003               = 20003, /**< IBM5550 Taiwan */
  CP_X_CP20004               = 20004, /**< TeleText Taiwan */
  CP_X_CP20005               = 20005, /**< Wang Taiwan */
  CP_X_IA5                   = 20105, /**< IA5 (IRV International Alphabet No. 5, 7-bit); Western European (IA5) */
  CP_X_IA5_GERMAN            = 20106, /**< IA5 German (7-bit) */
  CP_X_IA5_SWEDISH           = 20107, /**< IA5 Swedish (7-bit) */
  CP_X_IA5_NORWEGIAN         = 20108, /**< IA5 Norwegian (7-bit) */
  CP_US_ASCII                = 20127, /**< US-ASCII (7-bit) */
  CP_X_CP20261               = 20261, /**< T.61 */
  CP_X_CP20269               = 20269, /**< ISO 6937 Non-Spacing Accent */
  CP_IBM273                  = 20273, /**< IBM EBCDIC Germany */
  CP_IBM277                  = 20277, /**< IBM EBCDIC Denmark-Norway */
  CP_IBM278                  = 20278, /**< IBM EBCDIC Finland-Sweden */
  CP_IBM280                  = 20280, /**< IBM EBCDIC Italy */
  CP_IBM284                  = 20284, /**< IBM EBCDIC Latin America-Spain */
  CP_IBM285                  = 20285, /**< IBM EBCDIC United Kingdom */
  CP_IBM290                  = 20290, /**< IBM EBCDIC Japanese Katakana Extended */
  CP_IBM297                  = 20297, /**< IBM EBCDIC France */
  CP_IBM420                  = 20420, /**< IBM EBCDIC Arabic */
  CP_IBM423                  = 20423, /**< IBM EBCDIC Greek */
  CP_IBM424                  = 20424, /**< IBM EBCDIC Hebrew */
  CP_X_EBCDIC_KOREANEXTENDED = 20833, /**< IBM EBCDIC Korean Extended */
  CP_IBM_THAI                = 20838, /**< IBM EBCDIC Thai */
  CP_KOI8_R                  = 20866, /**< Russian (KOI8-R); Cyrillic (KOI8-R) */
  CP_IBM871                  = 20871, /**< IBM EBCDIC Icelandic */
  CP_IBM880                  = 20880, /**< IBM EBCDIC Cyrillic Russian */
  CP_IBM905                  = 20905, /**< IBM EBCDIC Turkish */
  CP_IBM00924                = 20924, /**< IBM EBCDIC Latin 1/Open System (1047 + Euro symbol) */
  CP_EUC_JP_JIS              = 20932, /**< Japanese (JIS 0208-1990 and 0121-1990) */
  CP_X_CP20936               = 20936, /**< Simplified Chinese (GB2312); Chinese Simplified (GB2312-80) */
  CP_X_CP20949               = 20949, /**< Korean Wansung */
  CP_CP1025                  = 21025, /**< IBM EBCDIC Cyrillic Serbian-Bulgarian */
  CP_KOI8_U                  = 21866, /**< Ukrainian (KOI8-U); Cyrillic (KOI8-U) */
  CP_ISO_8859_1              = 28591, /**< ISO 8859-1 Latin 1; Western European (ISO) */
  CP_ISO_8859_2              = 28592, /**< ISO 8859-2 Central European; Central European (ISO) */
  CP_ISO_8859_3              = 28593, /**< ISO 8859-3 Latin 3 */
  CP_ISO_8859_4              = 28594, /**< ISO 8859-4 Baltic */
  CP_ISO_8859_5              = 28595, /**< ISO 8859-5 Cyrillic */
  CP_ISO_8859_6              = 28596, /**< ISO 8859-6 Arabic */
  CP_ISO_8859_7              = 28597, /**< ISO 8859-7 Greek */
  CP_ISO_8859_8              = 28598, /**< ISO 8859-8 Hebrew; Hebrew (ISO-Visual) */
  CP_ISO_8859_9              = 28599, /**< ISO 8859-9 Turkish */
  CP_ISO_8859_13             = 28603, /**< ISO 8859-13 Estonian */
  CP_ISO_8859_15             = 28605, /**< ISO 8859-15 Latin 9 */
  CP_X_EUROPA                = 29001, /**< Europa 3 */
  CP_ISO_8859_8_I            = 38598, /**< ISO 8859-8 Hebrew; Hebrew (ISO-Logical) */
  CP_ISO_2022_JP             = 50220, /**< ISO 2022 Japanese with no halfwidth Katakana; Japanese (JIS) */
  CP_CSISO2022JP             = 50221, /**< ISO 2022 Japanese with halfwidth Katakana; Japanese (JIS-Allow 1 byte Kana) */
  CP_ISO_2022_JP_JIS         = 50222, /**< ISO 2022 Japanese JIS X 0201-1989; Japanese (JIS-Allow 1 byte Kana - SO/SI) */
  CP_ISO_2022_KR             = 50225, /**< ISO 2022 Korean */
  CP_X_CP50227               = 50227, /**< ISO 2022 Simplified Chinese; Chinese Simplified (ISO 2022) */
  CP_EUC_JP                  = 51932, /**< EUC Japanese */
  CP_EUC_CN                  = 51936, /**< EUC Simplified Chinese; Chinese Simplified (EUC) */
  CP_EUC_KR                  = 51949, /**< EUC Korean */
  CP_HZ_GB_2312              = 52936, /**< HZ-GB2312 Simplified Chinese; Chinese Simplified (HZ) */
  CP_GB18030                 = 54936, /**< Windows XP and later: GB18030 Simplified Chinese (4 byte); Chinese Simplified (GB18030) */
  CP_X_ISCII_DE              = 57002, /**< ISCII Devanagari */
  CP_X_ISCII_BE              = 57003, /**< ISCII Bengali */
  CP_X_ISCII_TA              = 57004, /**< ISCII Tamil */
  CP_X_ISCII_TE              = 57005, /**< ISCII Telugu */
  CP_X_ISCII_AS              = 57006, /**< ISCII Assamese */
  CP_X_ISCII_OR              = 57007, /**< ISCII Oriya */
  CP_X_ISCII_KA              = 57008, /**< ISCII Kannada */
  CP_X_ISCII_MA              = 57009, /**< ISCII Malayalam */
  CP_X_ISCII_GU              = 57010, /**< ISCII Gujarati */
  CP_X_ISCII_PA              = 57011, /**< ISCII Punjabi */
  CP_UTF_7                   = 65000, /**< Unicode (UTF-7) */
  CP_UTF_8                   = 65001, /**< Unicode (UTF-8) */
};

//! From https://docs.microsoft.com/en-us/windows/win32/menurc/acceltableentry
enum class ACCELERATOR_FLAGS: size_t  {
  FVIRTKEY  = 0x01,
  FNOINVERT = 0x02,
  FSHIFT    = 0x04,
  FCONTROL  = 0x08,
  FALT      = 0x10,
  END       = 0x80,
};

//! From https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
enum class ACCELERATOR_VK_CODES: size_t  {
  VK_LBUTTON             = 0x01,
  VK_RBUTTON             = 0x02,
  VK_CANCEL              = 0x03,
  VK_MBUTTON             = 0x04,
  VK_XBUTTON1            = 0x05,
  VK_XBUTTON2            = 0x06,
  VK_BACK                = 0x08,
  VK_TAB                 = 0x09,
  VK_CLEAR               = 0x0C,
  VK_RETURN              = 0x0D,
  VK_SHIFT               = 0x10,
  VK_CONTROL             = 0x11,
  VK_MENU                = 0x12,
  VK_PAUSE               = 0x13,
  VK_CAPITAL             = 0x14,
  VK_KANA                = 0x15,
  VK_HANGUEL             = 0x15,
  VK_HANGUL              = 0x15,
  VK_IME_ON              = 0x16,
  VK_JUNJA               = 0x17,
  VK_FINAL               = 0x18,
  VK_HANJA               = 0x19,
  VK_KANJI               = 0x19,
  VK_IME_OFF             = 0x1A,
  VK_ESCAPE              = 0x1B,
  VK_CONVERT             = 0x1C,
  VK_NONCONVERT          = 0x1D,
  VK_ACCEPT              = 0x1E,
  VK_MODECHANGE          = 0x1F,
  VK_SPACE               = 0x20,
  VK_PRIOR               = 0x21,
  VK_NEXT                = 0x22,
  VK_END                 = 0x23,
  VK_HOME                = 0x24,
  VK_LEFT                = 0x25,
  VK_UP                  = 0x26,
  VK_RIGHT               = 0x27,
  VK_DOWN                = 0x28,
  VK_SELECT              = 0x29,
  VK_PRINT               = 0x2A,
  VK_EXECUTE             = 0x2B,
  VK_SNAPSHOT            = 0x2C,
  VK_INSERT              = 0x2D,
  VK_DELETE              = 0x2E,
  VK_HELP                = 0x2F,
  VK_0                   = 0x30,
  VK_1                   = 0x31,
  VK_2                   = 0x32,
  VK_3                   = 0x33,
  VK_4                   = 0x34,
  VK_5                   = 0x35,
  VK_6                   = 0x36,
  VK_7                   = 0x37,
  VK_8                   = 0x38,
  VK_9                   = 0x39,
  VK_A                   = 0x41,
  VK_B                   = 0x42,
  VK_C                   = 0x43,
  VK_D                   = 0x44,
  VK_E                   = 0x45,
  VK_F                   = 0x46,
  VK_G                   = 0x47,
  VK_H                   = 0x48,
  VK_I                   = 0x49,
  VK_J                   = 0x4A,
  VK_K                   = 0x4B,
  VK_L                   = 0x4C,
  VK_M                   = 0x4D,
  VK_N                   = 0x4E,
  VK_O                   = 0x4F,
  VK_P                   = 0x50,
  VK_Q                   = 0x51,
  VK_R                   = 0x52,
  VK_S                   = 0x53,
  VK_T                   = 0x54,
  VK_U                   = 0x55,
  VK_V                   = 0x56,
  VK_W                   = 0x57,
  VK_X                   = 0x58,
  VK_Y                   = 0x59,
  VK_Z                   = 0x60,
  VK_LWIN                = 0x5B,
  VK_RWIN                = 0x5C,
  VK_APPS                = 0x5D,
  VK_SLEEP               = 0x5F,
  VK_NUMPAD0             = 0x60,
  VK_NUMPAD1             = 0x61,
  VK_NUMPAD2             = 0x62,
  VK_NUMPAD3             = 0x63,
  VK_NUMPAD4             = 0x64,
  VK_NUMPAD5             = 0x65,
  VK_NUMPAD6             = 0x66,
  VK_NUMPAD7             = 0x67,
  VK_NUMPAD8             = 0x68,
  VK_NUMPAD9             = 0x69,
  VK_MULTIPLY            = 0x6A,
  VK_ADD                 = 0x6B,
  VK_SEPARATOR           = 0x6C,
  VK_SUBTRACT            = 0x6D,
  VK_DECIMAL             = 0x6E,
  VK_DIVIDE              = 0x6F,
  VK_F1                  = 0x70,
  VK_F2                  = 0x71,
  VK_F3                  = 0x72,
  VK_F4                  = 0x73,
  VK_F5                  = 0x74,
  VK_F6                  = 0x75,
  VK_F7                  = 0x76,
  VK_F8                  = 0x77,
  VK_F9                  = 0x78,
  VK_F10                 = 0x79,
  VK_F11                 = 0x7A,
  VK_F12                 = 0x7B,
  VK_F13                 = 0x7C,
  VK_F14                 = 0x7D,
  VK_F15                 = 0x7E,
  VK_F16                 = 0x7F,
  VK_F17                 = 0x80,
  VK_F18                 = 0x81,
  VK_F19                 = 0x82,
  VK_F20                 = 0x83,
  VK_F21                 = 0x84,
  VK_F22                 = 0x85,
  VK_F23                 = 0x86,
  VK_F24                 = 0x87,
  VK_NUMLOCK             = 0x90,
  VK_SCROLL              = 0x91,
  VK_LSHIFT              = 0xA0,
  VK_RSHIFT              = 0xA1,
  VK_LCONTROL            = 0xA2,
  VK_RCONTROL            = 0xA3,
  VK_LMENU               = 0xA4,
  VK_RMENU               = 0xA5,
  VK_BROWSER_BACK        = 0xA6,
  VK_BROWSER_FORWARD     = 0xA7,
  VK_BROWSER_REFRESH     = 0xA8,
  VK_BROWSER_STOP        = 0xA9,
  VK_BROWSER_SEARCH      = 0xAA,
  VK_BROWSER_FAVORITES   = 0xAB,
  VK_BROWSER_HOME        = 0xAC,
  VK_VOLUME_MUTE         = 0xAD,
  VK_VOLUME_DOWN         = 0xAE,
  VK_VOLUME_UP           = 0xAF,
  VK_MEDIA_NEXT_TRACK    = 0xB0,
  VK_MEDIA_PREV_TRACK    = 0xB1,
  VK_MEDIA_STOP          = 0xB2,
  VK_MEDIA_PLAY_PAUSE    = 0xB3,
  VK_LAUNCH_MAIL         = 0xB4,
  VK_LAUNCH_MEDIA_SELECT = 0xB5,
  VK_LAUNCH_APP1         = 0xB6,
  VK_LAUNCH_APP2         = 0xB7,
  VK_OEM_1               = 0xBA,
  VK_OEM_PLUS            = 0xBB,
  VK_OEM_COMMA           = 0xBC,
  VK_OEM_MINUS           = 0xBD,
  VK_OEM_PERIOD          = 0xBE,
  VK_OEM_2               = 0xBF,
  VK_OEM_4               = 0xDB,
  VK_OEM_5               = 0xDC,
  VK_OEM_6               = 0xDD,
  VK_OEM_7               = 0xDE,
  VK_OEM_8               = 0xDF,
  VK_OEM_102             = 0xE2,
  VK_PROCESSKEY          = 0xE5,
  VK_PACKET              = 0xE7,
  VK_ATTN                = 0xF6,
  VK_CRSEL               = 0xF7,
  VK_EXSEL               = 0xF8,
  VK_EREOF               = 0xF9,
  VK_PLAY                = 0xFA,
  VK_ZOOM                = 0xFB,
  VK_NONAME              = 0xFC,
  VK_PA1                 = 0xFD,
  VK_OEM_CLEAR           = 0xFE,
};


//! Common section type
enum class PE_SECTION_TYPES : uint8_t {
  TEXT       = 0,
  TLS        = 1,
  IMPORT     = 2,
  DATA       = 3,
  BSS        = 4,
  RESOURCE   = 5,
  RELOCATION = 6,
  EXPORT     = 7,
  DEBUG_TYPE = 8,
  LOAD_CONFIG = 9,
  UNKNOWN     = 10
};

enum class PE_TYPE : uint16_t {
    PE32      = 0x10b, ///< 32bits
    PE32_PLUS = 0x20b  ///< 64 bits
};

//! Cryptography algorithms
enum class ALGORITHMS : uint32_t {
  UNKNOWN = 0,
  SHA_512,
  SHA_384,
  SHA_256,
  SHA_1,

  MD5,
  MD4,
  MD2,

  RSA,
  EC,

  MD5_RSA,
  SHA1_DSA,
  SHA1_RSA,
  SHA_256_RSA,
  SHA_384_RSA,
  SHA_512_RSA,
  SHA1_ECDSA,
  SHA_256_ECDSA,
  SHA_384_ECDSA,
  SHA_512_ECDSA,
};

}
}

ENABLE_BITMASK_OPERATORS(LIEF::PE::ACCELERATOR_FLAGS)
#endif
