/* Copyright 2021 - 2022 R. Thomas
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
#ifndef LIEF_PE_ENUMS_H_
#define LIEF_PE_ENUMS_H_
#include <inttypes.h>
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

enum class MACHINE_TYPES: size_t  {
  MT_Invalid = 0xffff,
  IMAGE_FILE_MACHINE_UNKNOWN   = 0x0,
  IMAGE_FILE_MACHINE_AM33      = 0x1D3,  /**< Matsushita AM33               */
  IMAGE_FILE_MACHINE_AMD64     = 0x8664, /**< AMD x64                        */
  IMAGE_FILE_MACHINE_ARM       = 0x1C0,  /**< ARM little endian              */
  IMAGE_FILE_MACHINE_ARMNT     = 0x1C4,  /**< ARMv7 Thumb mode only          */
  IMAGE_FILE_MACHINE_ARM64     = 0xAA64, /**< ARMv8 in 64-bits mode          */
  IMAGE_FILE_MACHINE_EBC       = 0xEBC,  /**< EFI byte code                  */
  IMAGE_FILE_MACHINE_I386      = 0x14C,  /**< Intel 386 or later             */
  IMAGE_FILE_MACHINE_IA64      = 0x200,  /**< Intel Itanium processor family */
  IMAGE_FILE_MACHINE_M32R      = 0x9041, /**< Mitsubishi M32R little endian  */
  IMAGE_FILE_MACHINE_MIPS16    = 0x266,  /**< MIPS16                         */
  IMAGE_FILE_MACHINE_MIPSFPU   = 0x366,  /**< MIPS with FPU                  */
  IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466,  /**< MIPS16 with FPU                */
  IMAGE_FILE_MACHINE_POWERPC   = 0x1F0,  /**< Power PC little endian         */
  IMAGE_FILE_MACHINE_POWERPCFP = 0x1F1,  /**< Power PC with floating point   */
  IMAGE_FILE_MACHINE_R4000     = 0x166,  /**< MIPS with little endian        */
  IMAGE_FILE_MACHINE_RISCV32   = 0x5032, /**< RISC-V 32-bit address space    */
  IMAGE_FILE_MACHINE_RISCV64   = 0x5064, /**< RISC-V 64-bit address space    */
  IMAGE_FILE_MACHINE_RISCV128  = 0x5128,  /**< RISC-V 128-bit address space   */
  IMAGE_FILE_MACHINE_SH3       = 0x1A2,  /**< Hitachi SH3                    */
  IMAGE_FILE_MACHINE_SH3DSP    = 0x1A3,  /**< Hitachi SH3 DSP                */
  IMAGE_FILE_MACHINE_SH4       = 0x1A6,  /**< Hitachi SH4                    */
  IMAGE_FILE_MACHINE_SH5       = 0x1A8,  /**< Hitachi SH5                    */
  IMAGE_FILE_MACHINE_THUMB     = 0x1C2,  /**< ARM or Thumb                   */
  IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169   /**< MIPS little-endian WCE v2      */
};

enum SYMBOL_SECTION_NUMBER: int {
  IMAGE_SYM_DEBUG     = -2,
  IMAGE_SYM_ABSOLUTE  = -1,
  IMAGE_SYM_UNDEFINED = 0
};


enum class HEADER_CHARACTERISTICS: size_t  {
  IMAGE_FILE_INVALID                 = 0x0000,
  IMAGE_FILE_RELOCS_STRIPPED         = 0x0001, /**< The file does not contain base relocations and must be loaded at its preferred base. If this cannot be done, the loader will error.*/
  IMAGE_FILE_EXECUTABLE_IMAGE        = 0x0002, /**< The file is valid and can be run.*/
  IMAGE_FILE_LINE_NUMS_STRIPPED      = 0x0004, /**< COFF line numbers have been stripped. This is deprecated and should be 0*/
  IMAGE_FILE_LOCAL_SYMS_STRIPPED     = 0x0008, /**< COFF symbol table entries for local symbols have been removed. This is deprecated and should be 0.*/
  IMAGE_FILE_AGGRESSIVE_WS_TRIM      = 0x0010, /**< Aggressively trim working set. This is deprecated and must be 0.*/
  IMAGE_FILE_LARGE_ADDRESS_AWARE     = 0x0020, /**< Image can handle > 2GiB addresses. */
  IMAGE_FILE_BYTES_REVERSED_LO       = 0x0080, /**< Little endian: the LSB precedes the MSB in memory. This is deprecated and should be 0.*/
  IMAGE_FILE_32BIT_MACHINE           = 0x0100, /**< Machine is based on a 32bit word architecture. */
  IMAGE_FILE_DEBUG_STRIPPED          = 0x0200, /**< Debugging info has been removed. */
  IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400, /**< If the image is on removable media, fully load it and copy it to swap. */
  IMAGE_FILE_NET_RUN_FROM_SWAP       = 0x0800, /**< If the image is on network media, fully load it and copy it to swap. */
  IMAGE_FILE_SYSTEM                  = 0x1000, /**< The image file is a system file, not a user program.*/
  IMAGE_FILE_DLL                     = 0x2000, /**< The image file is a DLL. */
  IMAGE_FILE_UP_SYSTEM_ONLY          = 0x4000, /**< This file should only be run on a uniprocessor machine. */
  IMAGE_FILE_BYTES_REVERSED_HI       = 0x8000  /**< Big endian: the MSB precedes the LSB in memory. This is deprecated */
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


enum class RELOCATIONS_BASE_TYPES: size_t  {
  IMAGE_REL_BASED_ABSOLUTE       = 0,
  IMAGE_REL_BASED_HIGH           = 1,
  IMAGE_REL_BASED_LOW            = 2,
  IMAGE_REL_BASED_HIGHLOW        = 3,
  IMAGE_REL_BASED_HIGHADJ        = 4,
  IMAGE_REL_BASED_MIPS_JMPADDR   = 5,
  IMAGE_REL_BASED_ARM_MOV32A     = 5,
  IMAGE_REL_BASED_ARM_MOV32      = 5,
  IMAGE_REL_BASED_RISCV_HI20     = 5,
  IMAGE_REL_BASED_SECTION        = 6,
  IMAGE_REL_BASED_REL            = 7,
  IMAGE_REL_BASED_ARM_MOV32T     = 7,
  IMAGE_REL_BASED_THUMB_MOV32    = 7,
  IMAGE_REL_BASED_RISCV_LOW12I   = 7,
  IMAGE_REL_BASED_RISCV_LOW12S   = 8,
  IMAGE_REL_BASED_MIPS_JMPADDR16 = 9,
  IMAGE_REL_BASED_IA64_IMM64     = 9,
  IMAGE_REL_BASED_DIR64          = 10,
  IMAGE_REL_BASED_HIGH3ADJ       = 11,
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


enum class DATA_DIRECTORY: size_t  {
  EXPORT_TABLE            = 0,
  IMPORT_TABLE            = 1,
  RESOURCE_TABLE          = 2,
  EXCEPTION_TABLE         = 3,
  CERTIFICATE_TABLE       = 4,
  BASE_RELOCATION_TABLE   = 5,
  DEBUG                   = 6,
  ARCHITECTURE            = 7,
  GLOBAL_PTR              = 8,
  TLS_TABLE               = 9,
  LOAD_CONFIG_TABLE       = 10,
  BOUND_IMPORT            = 11,
  IAT                     = 12,
  DELAY_IMPORT_DESCRIPTOR = 13,
  CLR_RUNTIME_HEADER      = 14,
  RESERVED                = 15,

  NUM_DATA_DIRECTORIES    = 16
};


enum class SUBSYSTEM: size_t  {
  IMAGE_SUBSYSTEM_UNKNOWN                  = 0,  ///< An unknown subsystem.
  IMAGE_SUBSYSTEM_NATIVE                   = 1,  ///< Device drivers and native Windows processes
  IMAGE_SUBSYSTEM_WINDOWS_GUI              = 2,  ///< The Windows GUI subsystem.
  IMAGE_SUBSYSTEM_WINDOWS_CUI              = 3,  ///< The Windows character subsystem.
  IMAGE_SUBSYSTEM_OS2_CUI                  = 5,  ///< The OS/2 character subsytem.
  IMAGE_SUBSYSTEM_POSIX_CUI                = 7,  ///< The POSIX character subsystem.
  IMAGE_SUBSYSTEM_NATIVE_WINDOWS           = 8,  ///< Native Windows 9x driver.
  IMAGE_SUBSYSTEM_WINDOWS_CE_GUI           = 9,  ///< Windows CE.
  IMAGE_SUBSYSTEM_EFI_APPLICATION          = 10, ///< An EFI application.
  IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  = 11, ///< An EFI driver with boot services.
  IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER       = 12, ///< An EFI driver with run-time services.
  IMAGE_SUBSYSTEM_EFI_ROM                  = 13, ///< An EFI ROM image.
  IMAGE_SUBSYSTEM_XBOX                     = 14, ///< XBOX.
  IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16  ///< A BCD application.
};

enum class DLL_CHARACTERISTICS: size_t  {
  IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA       = 0x0020, ///< ASLR with 64 bit address space.
  IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE          = 0x0040, ///< DLL can be relocated at load time.
  IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY       = 0x0080, ///< Code integrity checks are enforced.
  IMAGE_DLL_CHARACTERISTICS_NX_COMPAT             = 0x0100, ///< Image is NX compatible.
  IMAGE_DLL_CHARACTERISTICS_NO_ISOLATION          = 0x0200, ///< Isolation aware, but do not isolate the image.
  IMAGE_DLL_CHARACTERISTICS_NO_SEH                = 0x0400, ///< Does not use structured exception handling (SEH). No SEH handler may be called in this image.
  IMAGE_DLL_CHARACTERISTICS_NO_BIND               = 0x0800, ///< Do not bind the image.
  IMAGE_DLL_CHARACTERISTICS_APPCONTAINER          = 0x1000, ///< Image should execute in an AppContainer.
  IMAGE_DLL_CHARACTERISTICS_WDM_DRIVER            = 0x2000, ///< A WDM driver.
  IMAGE_DLL_CHARACTERISTICS_GUARD_CF              = 0x4000, ///< Image supports Control Flow Guard.
  IMAGE_DLL_CHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000  ///< Terminal Server aware.
};


enum class DEBUG_TYPES: size_t  {
  IMAGE_DEBUG_TYPE_UNKNOWN               = 0,
  IMAGE_DEBUG_TYPE_COFF                  = 1, ///< COFF debug information
  IMAGE_DEBUG_TYPE_CODEVIEW              = 2, ///< CodeView debug information (pdb & cie)
  IMAGE_DEBUG_TYPE_FPO                   = 3, ///< Frame pointer omission information
  IMAGE_DEBUG_TYPE_MISC                  = 4, ///< CodeView Debug Information
  IMAGE_DEBUG_TYPE_EXCEPTION             = 5, ///< A copy of .pdata section.
  IMAGE_DEBUG_TYPE_FIXUP                 = 6, ///< Reserved.
  IMAGE_DEBUG_TYPE_OMAP_TO_SRC           = 7, ///< The mapping from an RVA in image to an RVA in source image.
  IMAGE_DEBUG_TYPE_OMAP_FROM_SRC         = 8, ///< The mapping from an RVA in source image to an RVA in image.
  IMAGE_DEBUG_TYPE_BORLAND               = 9, ///< Reserved for Borland.
  IMAGE_DEBUG_TYPE_RESERVED10            = 10, ///< Reserved for future use.
  IMAGE_DEBUG_TYPE_CLSID                 = 11,
  IMAGE_DEBUG_TYPE_VC_FEATURE            = 12,
  IMAGE_DEBUG_TYPE_POGO                  = 13,
  IMAGE_DEBUG_TYPE_ILTCG                 = 14,
  IMAGE_DEBUG_TYPE_MPX                   = 15,
  IMAGE_DEBUG_TYPE_REPRO                 = 16,
  IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS = 20,
};


//! Code view signatures
//! @see: http://llvm.org/doxygen/CVDebugRecord_8h_source.html
enum class CODE_VIEW_SIGNATURES: size_t  {
  CVS_UNKNOWN = 0,
  CVS_PDB_70 = 0x53445352, // RSDS
  CVS_PDB_20 = 0x3031424e, // NB10
  CVS_CV_50  = 0x3131424e, // NB11
  CVS_CV_41  = 0x3930424e, // NB09
};

enum class POGO_SIGNATURES: size_t  {
  POGO_UNKNOWN = 0,
  POGO_LCTG    = 0x4C544347,  // LCTG
  POGO_PGI     = 0x50474900 , // PGI\0
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


//
// Resources
//

//! From https://docs.microsoft.com/en-us/windows/win32/menurc/resource-types
enum class RESOURCE_TYPES: size_t  {
  CURSOR       = 1,
  BITMAP       = 2,
  ICON         = 3,
  MENU         = 4,
  DIALOG       = 5,
  STRING       = 6,
  FONTDIR      = 7,
  FONT         = 8,
  ACCELERATOR  = 9,
  RCDATA       = 10,
  MESSAGETABLE = 11,
  GROUP_CURSOR = 12,
  GROUP_ICON   = 14,
  VERSION      = 16,
  DLGINCLUDE   = 17,
  PLUGPLAY     = 19,
  VXD          = 20,
  ANICURSOR    = 21,
  ANIICON      = 22,
  HTML         = 23,
  MANIFEST     = 24
};

enum class RESOURCE_LANGS: size_t  {
  LANG_NEUTRAL        = 0x00,
  LANG_INVARIANT      = 0x7f,
  LANG_AFRIKAANS      = 0x36,
  LANG_ALBANIAN       = 0x1c,
  LANG_ARABIC         = 0x01,
  LANG_ARMENIAN       = 0x2b,
  LANG_ASSAMESE       = 0x4d,
  LANG_AZERI          = 0x2c,
  LANG_BASQUE         = 0x2d,
  LANG_BELARUSIAN     = 0x23,
  LANG_BANGLA         = 0x45,
  LANG_BULGARIAN      = 0x02,
  LANG_CATALAN        = 0x03,
  LANG_CHINESE        = 0x04,
  LANG_CROATIAN       = 0x1a,
  LANG_BOSNIAN        = 0x1a,
  LANG_CZECH          = 0x05,
  LANG_DANISH         = 0x06,
  LANG_DIVEHI         = 0x65,
  LANG_DUTCH          = 0x13,
  LANG_ENGLISH        = 0x09,
  LANG_ESTONIAN       = 0x25,
  LANG_FAEROESE       = 0x38,
  LANG_FARSI          = 0x29,
  LANG_FINNISH        = 0x0b,
  LANG_FRENCH         = 0x0c,
  LANG_GALICIAN       = 0x56,
  LANG_GEORGIAN       = 0x37,
  LANG_GERMAN         = 0x07,
  LANG_GREEK          = 0x08,
  LANG_GUJARATI       = 0x47,
  LANG_HEBREW         = 0x0d,
  LANG_HINDI          = 0x39,
  LANG_HUNGARIAN      = 0x0e,
  LANG_ICELANDIC      = 0x0f,
  LANG_INDONESIAN     = 0x21,
  LANG_ITALIAN        = 0x10,
  LANG_JAPANESE       = 0x11,
  LANG_KANNADA        = 0x4b,
  LANG_KASHMIRI       = 0x60,
  LANG_KAZAK          = 0x3f,
  LANG_KONKANI        = 0x57,
  LANG_KOREAN         = 0x12,
  LANG_KYRGYZ         = 0x40,
  LANG_LATVIAN        = 0x26,
  LANG_LITHUANIAN     = 0x27,
  LANG_MACEDONIAN     = 0x2f,
  LANG_MALAY          = 0x3e,
  LANG_MALAYALAM      = 0x4c,
  LANG_MANIPURI       = 0x58,
  LANG_MARATHI        = 0x4e,
  LANG_MONGOLIAN      = 0x50,
  LANG_NEPALI         = 0x61,
  LANG_NORWEGIAN      = 0x14,
  LANG_ORIYA          = 0x48,
  LANG_POLISH         = 0x15,
  LANG_PORTUGUESE     = 0x16,
  LANG_PUNJABI        = 0x46,
  LANG_ROMANIAN       = 0x18,
  LANG_RUSSIAN        = 0x19,
  LANG_SANSKRIT       = 0x4f,
  LANG_SERBIAN        = 0x1a,
  LANG_SINDHI         = 0x59,
  LANG_SLOVAK         = 0x1b,
  LANG_SLOVENIAN      = 0x24,
  LANG_SPANISH        = 0x0a,
  LANG_SWAHILI        = 0x41,
  LANG_SWEDISH        = 0x1d,
  LANG_SYRIAC         = 0x5a,
  LANG_TAMIL          = 0x49,
  LANG_TATAR          = 0x44,
  LANG_TELUGU         = 0x4a,
  LANG_THAI           = 0x1e,
  LANG_TURKISH        = 0x1f,
  LANG_UKRAINIAN      = 0x22,
  LANG_URDU           = 0x20,
  LANG_UZBEK          = 0x43,
  LANG_VIETNAMESE     = 0x2a,
  LANG_GAELIC         = 0x3c,
  LANG_MALTESE        = 0x3a,
  LANG_MAORI          = 0x28,
  LANG_RHAETO_ROMANCE = 0x17,
  LANG_SAMI           = 0x3b,
  LANG_SORBIAN        = 0x2e,
  LANG_SUTU           = 0x30,
  LANG_TSONGA         = 0x31,
  LANG_TSWANA         = 0x32,
  LANG_VENDA          = 0x33,
  LANG_XHOSA          = 0x34,
  LANG_ZULU           = 0x35,
  LANG_ESPERANTO      = 0x8f,
  LANG_WALON          = 0x90,
  LANG_CORNISH        = 0x91,
  LANG_WELSH          = 0x92,
  LANG_BRETON         = 0x93,
  LANG_INUKTITUT      = 0x5d,
  LANG_IRISH          = 0x3C,
  LANG_LOWER_SORBIAN  = 0x2E,
  LANG_PULAR          = 0x67,
  LANG_QUECHUA        = 0x6B,
  LANG_TAMAZIGHT      = 0x5F,
  LANG_TIGRINYA       = 0x73,
  LANG_VALENCIAN      = 0x03,
};

enum class RESOURCE_SUBLANGS: size_t  {
  SUBLANG_AFRIKAANS_SOUTH_AFRICA = 0,
  SUBLANG_ALBANIAN_ALBANIA,
  SUBLANG_ALSATIAN_FRANCE,
  SUBLANG_AMHARIC_ETHIOPIA,
  SUBLANG_ARABIC_ALGERIA,
  SUBLANG_ARABIC_BAHRAIN,
  SUBLANG_ARABIC_EGYPT,
  SUBLANG_ARABIC_IRAQ,
  SUBLANG_ARABIC_JORDAN,
  SUBLANG_ARABIC_KUWAIT,
  SUBLANG_ARABIC_LEBANON,
  SUBLANG_ARABIC_LIBYA,
  SUBLANG_ARABIC_MOROCCO,
  SUBLANG_ARABIC_OMAN,
  SUBLANG_ARABIC_QATAR,
  SUBLANG_ARABIC_SAUDI_ARABIA,
  SUBLANG_ARABIC_SYRIA,
  SUBLANG_ARABIC_TUNISIA,
  SUBLANG_ARABIC_UAE,
  SUBLANG_ARABIC_YEMEN,
  SUBLANG_ARMENIAN_ARMENIA,
  SUBLANG_ASSAMESE_INDIA,
  SUBLANG_AZERI_CYRILLIC,
  SUBLANG_AZERI_LATIN,
  SUBLANG_BASHKIR_RUSSIA,
  SUBLANG_BASQUE_BASQUE,
  SUBLANG_BELARUSIAN_BELARUS,
  SUBLANG_BANGLA_BANGLADESH,
  SUBLANG_BANGLA_INDIA,
  SUBLANG_BOSNIAN_BOSNIA_HERZEGOVINA_CYRILLIC,
  SUBLANG_BOSNIAN_BOSNIA_HERZEGOVINA_LATIN,
  SUBLANG_BRETON_FRANCE,
  SUBLANG_BULGARIAN_BULGARIA,
  SUBLANG_CATALAN_CATALAN,
  SUBLANG_CHINESE_HONGKONG,
  SUBLANG_CHINESE_MACAU,
  SUBLANG_CHINESE_SIMPLIFIED,
  SUBLANG_CHINESE_SINGAPORE,
  SUBLANG_CHINESE_TRADITIONAL,
  SUBLANG_CORSICAN_FRANCE,
  SUBLANG_CROATIAN_BOSNIA_HERZEGOVINA_LATIN,
  SUBLANG_CROATIAN_CROATIA,
  SUBLANG_CUSTOM_DEFAULT,
  SUBLANG_CUSTOM_UNSPECIFIED,
  SUBLANG_CZECH_CZECH_REPUBLIC,
  SUBLANG_DANISH_DENMARK,
  SUBLANG_DARI_AFGHANISTAN,
  SUBLANG_DEFAULT,
  SUBLANG_DIVEHI_MALDIVES,
  SUBLANG_DUTCH_BELGIAN,
  SUBLANG_DUTCH,
  SUBLANG_ENGLISH_AUS,
  SUBLANG_ENGLISH_BELIZE,
  SUBLANG_ENGLISH_CAN,
  SUBLANG_ENGLISH_CARIBBEAN,
  SUBLANG_ENGLISH_EIRE,
  SUBLANG_ENGLISH_INDIA,
  SUBLANG_ENGLISH_JAMAICA,
  SUBLANG_ENGLISH_MALAYSIA,
  SUBLANG_ENGLISH_NZ,
  SUBLANG_ENGLISH_PHILIPPINES,
  SUBLANG_ENGLISH_SINGAPORE,
  SUBLANG_ENGLISH_SOUTH_AFRICA,
  SUBLANG_ENGLISH_TRINIDAD,
  SUBLANG_ENGLISH_UK,
  SUBLANG_ENGLISH_US,
  SUBLANG_ENGLISH_ZIMBABWE,
  SUBLANG_ENGLISH_IRELAND,
  SUBLANG_ESTONIAN_ESTONIA,
  SUBLANG_FAEROESE_FAROE_ISLANDS,
  SUBLANG_FILIPINO_PHILIPPINES,
  SUBLANG_FINNISH_FINLAND,
  SUBLANG_FRENCH_BELGIAN,
  SUBLANG_FRENCH_CANADIAN,
  SUBLANG_FRENCH_LUXEMBOURG,
  SUBLANG_FRENCH_MONACO,
  SUBLANG_FRENCH_SWISS,
  SUBLANG_FRENCH,
  SUBLANG_FRISIAN_NETHERLANDS,
  SUBLANG_GALICIAN_GALICIAN,
  SUBLANG_GEORGIAN_GEORGIA,
  SUBLANG_GERMAN_AUSTRIAN,
  SUBLANG_GERMAN_LIECHTENSTEIN,
  SUBLANG_GERMAN_LUXEMBOURG,
  SUBLANG_GERMAN_SWISS,
  SUBLANG_GERMAN,
  SUBLANG_GREEK_GREECE,
  SUBLANG_GREENLANDIC_GREENLAND,
  SUBLANG_GUJARATI_INDIA,
  SUBLANG_HAUSA_NIGERIA_LATIN,
  SUBLANG_HEBREW_ISRAEL,
  SUBLANG_HINDI_INDIA,
  SUBLANG_HUNGARIAN_HUNGARY,
  SUBLANG_ICELANDIC_ICELAND,
  SUBLANG_IGBO_NIGERIA,
  SUBLANG_INDONESIAN_INDONESIA,
  SUBLANG_INUKTITUT_CANADA_LATIN,
  SUBLANG_INUKTITUT_CANADA,
  SUBLANG_IRISH_IRELAND,
  SUBLANG_ITALIAN_SWISS,
  SUBLANG_ITALIAN,
  SUBLANG_JAPANESE_JAPAN,
  SUBLANG_KANNADA_INDIA,
  SUBLANG_KASHMIRI_INDIA,
  SUBLANG_KASHMIRI_SASIA,
  SUBLANG_KAZAK_KAZAKHSTAN,
  SUBLANG_KHMER_CAMBODIA,
  SUBLANG_KICHE_GUATEMALA,
  SUBLANG_KINYARWANDA_RWANDA,
  SUBLANG_KONKANI_INDIA,
  SUBLANG_KOREAN,
  SUBLANG_KYRGYZ_KYRGYZSTAN,
  SUBLANG_LAO_LAO,
  SUBLANG_LATVIAN_LATVIA,
  SUBLANG_LITHUANIAN_CLASSIC,
  SUBLANG_LITHUANIAN,
  SUBLANG_LOWER_SORBIAN_GERMANY,
  SUBLANG_LUXEMBOURGISH_LUXEMBOURG,
  SUBLANG_MACEDONIAN_MACEDONIA,
  SUBLANG_MALAY_BRUNEI_DARUSSALAM,
  SUBLANG_MALAY_MALAYSIA,
  SUBLANG_MALAYALAM_INDIA,
  SUBLANG_MALTESE_MALTA,
  SUBLANG_MAORI_NEW_ZEALAND,
  SUBLANG_MAPUDUNGUN_CHILE,
  SUBLANG_MARATHI_INDIA,
  SUBLANG_MOHAWK_MOHAWK,
  SUBLANG_MONGOLIAN_CYRILLIC_MONGOLIA,
  SUBLANG_MONGOLIAN_PRC,
  SUBLANG_NEPALI_INDIA,
  SUBLANG_NEPALI_NEPAL,
  SUBLANG_NEUTRAL,
  SUBLANG_NORWEGIAN_BOKMAL,
  SUBLANG_NORWEGIAN_NYNORSK,
  SUBLANG_OCCITAN_FRANCE,
  SUBLANG_ORIYA_INDIA,
  SUBLANG_PASHTO_AFGHANISTAN,
  SUBLANG_PERSIAN_IRAN,
  SUBLANG_POLISH_POLAND,
  SUBLANG_PORTUGUESE_BRAZILIAN,
  SUBLANG_PORTUGUESE,
  SUBLANG_PUNJABI_INDIA,
  SUBLANG_QUECHUA_BOLIVIA,
  SUBLANG_QUECHUA_ECUADOR,
  SUBLANG_QUECHUA_PERU,
  SUBLANG_ROMANIAN_ROMANIA,
  SUBLANG_ROMANSH_SWITZERLAND,
  SUBLANG_RUSSIAN_RUSSIA,
  SUBLANG_SAMI_INARI_FINLAND,
  SUBLANG_SAMI_LULE_NORWAY,
  SUBLANG_SAMI_LULE_SWEDEN,
  SUBLANG_SAMI_NORTHERN_FINLAND,
  SUBLANG_SAMI_NORTHERN_NORWAY,
  SUBLANG_SAMI_NORTHERN_SWEDEN,
  SUBLANG_SAMI_SKOLT_FINLAND,
  SUBLANG_SAMI_SOUTHERN_NORWAY,
  SUBLANG_SAMI_SOUTHERN_SWEDEN,
  SUBLANG_SANSKRIT_INDIA,
  SUBLANG_SERBIAN_BOSNIA_HERZEGOVINA_CYRILLIC,
  SUBLANG_SERBIAN_BOSNIA_HERZEGOVINA_LATIN,
  SUBLANG_SERBIAN_CROATIA,
  SUBLANG_SERBIAN_CYRILLIC,
  SUBLANG_SERBIAN_LATIN,
  SUBLANG_SINDHI_AFGHANISTAN,
  SUBLANG_SINDHI_INDIA,
  SUBLANG_SINDHI_PAKISTAN,
  SUBLANG_SINHALESE_SRI_LANKA,
  SUBLANG_SLOVAK_SLOVAKIA,
  SUBLANG_SLOVENIAN_SLOVENIA,
  SUBLANG_SOTHO_NORTHERN_SOUTH_AFRICA,
  SUBLANG_SPANISH_ARGENTINA,
  SUBLANG_SPANISH_BOLIVIA,
  SUBLANG_SPANISH_CHILE,
  SUBLANG_SPANISH_COLOMBIA,
  SUBLANG_SPANISH_COSTA_RICA,
  SUBLANG_SPANISH_DOMINICAN_REPUBLIC,
  SUBLANG_SPANISH_ECUADOR,
  SUBLANG_SPANISH_EL_SALVADOR,
  SUBLANG_SPANISH_GUATEMALA,
  SUBLANG_SPANISH_HONDURAS,
  SUBLANG_SPANISH_MEXICAN,
  SUBLANG_SPANISH_MODERN,
  SUBLANG_SPANISH_NICARAGUA,
  SUBLANG_SPANISH_PANAMA,
  SUBLANG_SPANISH_PARAGUAY,
  SUBLANG_SPANISH_PERU,
  SUBLANG_SPANISH_PUERTO_RICO,
  SUBLANG_SPANISH_URUGUAY,
  SUBLANG_SPANISH_US,
  SUBLANG_SPANISH_VENEZUELA,
  SUBLANG_SPANISH,
  SUBLANG_SWAHILI_KENYA,
  SUBLANG_SWEDISH_FINLAND,
  SUBLANG_SWEDISH,
  SUBLANG_SYRIAC_SYRIA,
  SUBLANG_SYS_DEFAULT,
  SUBLANG_TAJIK_TAJIKISTAN,
  SUBLANG_TAMAZIGHT_ALGERIA_LATIN,
  SUBLANG_TAMIL_INDIA,
  SUBLANG_TATAR_RUSSIA,
  SUBLANG_TELUGU_INDIA,
  SUBLANG_THAI_THAILAND,
  SUBLANG_TIBETAN_PRC,
  SUBLANG_TIGRIGNA_ERITREA,
  SUBLANG_TSWANA_SOUTH_AFRICA,
  SUBLANG_TURKISH_TURKEY,
  SUBLANG_TURKMEN_TURKMENISTAN,
  SUBLANG_UI_CUSTOM_DEFAULT,
  SUBLANG_UIGHUR_PRC,
  SUBLANG_UKRAINIAN_UKRAINE,
  SUBLANG_UPPER_SORBIAN_GERMANY,
  SUBLANG_URDU_INDIA,
  SUBLANG_URDU_PAKISTAN,
  SUBLANG_UZBEK_CYRILLIC,
  SUBLANG_UZBEK_LATIN,
  SUBLANG_VIETNAMESE_VIETNAM,
  SUBLANG_WELSH_UNITED_KINGDOM,
  SUBLANG_WOLOF_SENEGAL,
  SUBLANG_XHOSA_SOUTH_AFRICA,
  SUBLANG_YAKUT_RUSSIA,
  SUBLANG_YI_PRC,
  SUBLANG_YORUBA_NIGERIA,
  SUBLANG_ZULU_SOUTH_AFRICA,
  SUBLANG_PULAR_SENEGAL,
  SUBLANG_PUNJABI_PAKISTAN,
  SUBLANG_TSWANA_BOTSWANA,
  SUBLANG_TAMIL_SRI_LANKA,
  SUBLANG_TIGRINYA_ETHIOPIA,
  SUBLANG_TIGRINYA_ERITREA,
  SUBLANG_VALENCIAN_VALENCIA,
};


enum class SECTION_CHARACTERISTICS: size_t  {
  SC_Invalid = 0xffffffff,

  IMAGE_SCN_TYPE_NO_PAD            = 0x00000008,
  IMAGE_SCN_CNT_CODE               = 0x00000020,
  IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040,
  IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080,
  IMAGE_SCN_LNK_OTHER              = 0x00000100,
  IMAGE_SCN_LNK_INFO               = 0x00000200,
  IMAGE_SCN_LNK_REMOVE             = 0x00000800,
  IMAGE_SCN_LNK_COMDAT             = 0x00001000,
  IMAGE_SCN_GPREL                  = 0x00008000,
  IMAGE_SCN_MEM_PURGEABLE          = 0x00010000,
  IMAGE_SCN_MEM_16BIT              = 0x00020000,
  IMAGE_SCN_MEM_LOCKED             = 0x00040000,
  IMAGE_SCN_MEM_PRELOAD            = 0x00080000,
  IMAGE_SCN_ALIGN_1BYTES           = 0x00100000,
  IMAGE_SCN_ALIGN_2BYTES           = 0x00200000,
  IMAGE_SCN_ALIGN_4BYTES           = 0x00300000,
  IMAGE_SCN_ALIGN_8BYTES           = 0x00400000,
  IMAGE_SCN_ALIGN_16BYTES          = 0x00500000,
  IMAGE_SCN_ALIGN_32BYTES          = 0x00600000,
  IMAGE_SCN_ALIGN_64BYTES          = 0x00700000,
  IMAGE_SCN_ALIGN_128BYTES         = 0x00800000,
  IMAGE_SCN_ALIGN_256BYTES         = 0x00900000,
  IMAGE_SCN_ALIGN_512BYTES         = 0x00A00000,
  IMAGE_SCN_ALIGN_1024BYTES        = 0x00B00000,
  IMAGE_SCN_ALIGN_2048BYTES        = 0x00C00000,
  IMAGE_SCN_ALIGN_4096BYTES        = 0x00D00000,
  IMAGE_SCN_ALIGN_8192BYTES        = 0x00E00000,
  IMAGE_SCN_LNK_NRELOC_OVFL        = 0x01000000,
  IMAGE_SCN_MEM_DISCARDABLE        = 0x02000000,
  IMAGE_SCN_MEM_NOT_CACHED         = 0x04000000,
  IMAGE_SCN_MEM_NOT_PAGED          = 0x08000000,
  IMAGE_SCN_MEM_SHARED             = 0x10000000,
  IMAGE_SCN_MEM_EXECUTE            = 0x20000000,
  IMAGE_SCN_MEM_READ               = 0x40000000,
  IMAGE_SCN_MEM_WRITE              = 0x80000000
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

enum class WIN_VERSION: size_t  {
  WIN_UNKNOWN   = 0,
  WIN_SEH       = 1,
  WIN8_1        = 2,
  WIN10_0_9879  = 3,
  WIN10_0_14286 = 4,
  WIN10_0_14383 = 5,
  WIN10_0_14901 = 6,
  WIN10_0_15002 = 7,
  WIN10_0_16237 = 8,
};

enum class GUARD_CF_FLAGS: size_t  {
  GCF_NONE                            = 0x00000000,
  GCF_INSTRUMENTED                    = 0x00000100, /**< Module performs control flow integrity checks using system-supplied support */
  GCF_W_INSTRUMENTED                  = 0x00000200, /**< Module performs control flow and write integrity checks */
  GCF_FUNCTION_TABLE_PRESENT          = 0x00000400, /**< Module contains valid control flow target metadata */
  GCF_EXPORT_SUPPRESSION_INFO_PRESENT = 0x00004000, /**< Module contains suppressed export information. This also infers that the address taken taken IAT table is also present in the load config. */
  GCF_ENABLE_EXPORT_SUPPRESSION       = 0x00008000, /**< Module enables suppression of exports */
  GCF_LONGJUMP_TABLE_PRESENT          = 0x00010000, /**< Module contains longjmp target information */

  GRF_INSTRUMENTED                    = 0x00020000, /**< Module contains return flow instrumentation and metadata */
  GRF_ENABLE                          = 0x00040000, /**< Module requests that the OS enable return flow protection */
  GRF_STRICT                          = 0x00080000, /**< Module requests that the OS enable return flow protection in strict mode */
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
  DEBUG      = 8,
  LOAD_CONFIG = 9,
  UNKNOWN     = 10
};

enum class PE_TYPE : uint16_t {
    PE32      = 0x10b, ///< 32bits
    PE32_PLUS = 0x20b  ///< 64 bits
};

//! Cryptography algorithms
enum class ALGORITHMS {
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

//! Typed enum for LIEF::PE::Attribute
enum class SIG_ATTRIBUTE_TYPES {
  UNKNOWN = 0,
  CONTENT_TYPE,
  GENERIC_TYPE,

  SPC_SP_OPUS_INFO,

  MS_COUNTER_SIGN,
  MS_SPC_NESTED_SIGN,
  MS_SPC_STATEMENT_TYPE,

  PKCS9_AT_SEQUENCE_NUMBER,
  PKCS9_COUNTER_SIGNATURE,
  PKCS9_MESSAGE_DIGEST,
  PKCS9_SIGNING_TIME,
};


static const RESOURCE_TYPES resource_types_array[] = {
  RESOURCE_TYPES::CURSOR,
  RESOURCE_TYPES::BITMAP,
  RESOURCE_TYPES::ICON,
  RESOURCE_TYPES::MENU,
  RESOURCE_TYPES::DIALOG,
  RESOURCE_TYPES::STRING,
  RESOURCE_TYPES::FONTDIR,
  RESOURCE_TYPES::FONT,
  RESOURCE_TYPES::ACCELERATOR,
  RESOURCE_TYPES::RCDATA,
  RESOURCE_TYPES::MESSAGETABLE,
  RESOURCE_TYPES::GROUP_CURSOR,
  RESOURCE_TYPES::GROUP_ICON,
  RESOURCE_TYPES::VERSION,
  RESOURCE_TYPES::DLGINCLUDE,
  RESOURCE_TYPES::PLUGPLAY,
  RESOURCE_TYPES::VXD,
  RESOURCE_TYPES::ANICURSOR,
  RESOURCE_TYPES::ANIICON,
  RESOURCE_TYPES::HTML,
  RESOURCE_TYPES::MANIFEST,
};

static const RESOURCE_LANGS resource_langs_array[] = {
  RESOURCE_LANGS::LANG_NEUTRAL,
  RESOURCE_LANGS::LANG_INVARIANT,
  RESOURCE_LANGS::LANG_AFRIKAANS,
  RESOURCE_LANGS::LANG_ALBANIAN,
  RESOURCE_LANGS::LANG_ARABIC,
  RESOURCE_LANGS::LANG_ARMENIAN,
  RESOURCE_LANGS::LANG_ASSAMESE,
  RESOURCE_LANGS::LANG_AZERI,
  RESOURCE_LANGS::LANG_BASQUE,
  RESOURCE_LANGS::LANG_BELARUSIAN,
  RESOURCE_LANGS::LANG_BANGLA,
  RESOURCE_LANGS::LANG_BULGARIAN,
  RESOURCE_LANGS::LANG_CATALAN,
  RESOURCE_LANGS::LANG_CHINESE,
  RESOURCE_LANGS::LANG_CROATIAN,
  RESOURCE_LANGS::LANG_BOSNIAN,
  RESOURCE_LANGS::LANG_CZECH,
  RESOURCE_LANGS::LANG_DANISH,
  RESOURCE_LANGS::LANG_DIVEHI,
  RESOURCE_LANGS::LANG_DUTCH,
  RESOURCE_LANGS::LANG_ENGLISH,
  RESOURCE_LANGS::LANG_ESTONIAN,
  RESOURCE_LANGS::LANG_FAEROESE,
  RESOURCE_LANGS::LANG_FARSI,
  RESOURCE_LANGS::LANG_FINNISH,
  RESOURCE_LANGS::LANG_FRENCH,
  RESOURCE_LANGS::LANG_GALICIAN,
  RESOURCE_LANGS::LANG_GEORGIAN,
  RESOURCE_LANGS::LANG_GERMAN,
  RESOURCE_LANGS::LANG_GREEK,
  RESOURCE_LANGS::LANG_GUJARATI,
  RESOURCE_LANGS::LANG_HEBREW,
  RESOURCE_LANGS::LANG_HINDI,
  RESOURCE_LANGS::LANG_HUNGARIAN,
  RESOURCE_LANGS::LANG_ICELANDIC,
  RESOURCE_LANGS::LANG_INDONESIAN,
  RESOURCE_LANGS::LANG_ITALIAN,
  RESOURCE_LANGS::LANG_JAPANESE,
  RESOURCE_LANGS::LANG_KANNADA,
  RESOURCE_LANGS::LANG_KASHMIRI,
  RESOURCE_LANGS::LANG_KAZAK,
  RESOURCE_LANGS::LANG_KONKANI,
  RESOURCE_LANGS::LANG_KOREAN,
  RESOURCE_LANGS::LANG_KYRGYZ,
  RESOURCE_LANGS::LANG_LATVIAN,
  RESOURCE_LANGS::LANG_LITHUANIAN,
  RESOURCE_LANGS::LANG_MACEDONIAN,
  RESOURCE_LANGS::LANG_MALAY,
  RESOURCE_LANGS::LANG_MALAYALAM,
  RESOURCE_LANGS::LANG_MANIPURI,
  RESOURCE_LANGS::LANG_MARATHI,
  RESOURCE_LANGS::LANG_MONGOLIAN,
  RESOURCE_LANGS::LANG_NEPALI,
  RESOURCE_LANGS::LANG_NORWEGIAN,
  RESOURCE_LANGS::LANG_ORIYA,
  RESOURCE_LANGS::LANG_POLISH,
  RESOURCE_LANGS::LANG_PORTUGUESE,
  RESOURCE_LANGS::LANG_PUNJABI,
  RESOURCE_LANGS::LANG_ROMANIAN,
  RESOURCE_LANGS::LANG_RUSSIAN,
  RESOURCE_LANGS::LANG_SANSKRIT,
  RESOURCE_LANGS::LANG_SERBIAN,
  RESOURCE_LANGS::LANG_SINDHI,
  RESOURCE_LANGS::LANG_SLOVAK,
  RESOURCE_LANGS::LANG_SLOVENIAN,
  RESOURCE_LANGS::LANG_SPANISH,
  RESOURCE_LANGS::LANG_SWAHILI,
  RESOURCE_LANGS::LANG_SWEDISH,
  RESOURCE_LANGS::LANG_SYRIAC,
  RESOURCE_LANGS::LANG_TAMIL,
  RESOURCE_LANGS::LANG_TATAR,
  RESOURCE_LANGS::LANG_TELUGU,
  RESOURCE_LANGS::LANG_THAI,
  RESOURCE_LANGS::LANG_TURKISH,
  RESOURCE_LANGS::LANG_UKRAINIAN,
  RESOURCE_LANGS::LANG_URDU,
  RESOURCE_LANGS::LANG_UZBEK,
  RESOURCE_LANGS::LANG_VIETNAMESE,
  RESOURCE_LANGS::LANG_GAELIC,
  RESOURCE_LANGS::LANG_MALTESE,
  RESOURCE_LANGS::LANG_MAORI,
  RESOURCE_LANGS::LANG_RHAETO_ROMANCE,
  RESOURCE_LANGS::LANG_SAMI,
  RESOURCE_LANGS::LANG_SORBIAN,
  RESOURCE_LANGS::LANG_SUTU,
  RESOURCE_LANGS::LANG_TSONGA,
  RESOURCE_LANGS::LANG_TSWANA,
  RESOURCE_LANGS::LANG_VENDA,
  RESOURCE_LANGS::LANG_XHOSA,
  RESOURCE_LANGS::LANG_ZULU,
  RESOURCE_LANGS::LANG_ESPERANTO,
  RESOURCE_LANGS::LANG_WALON,
  RESOURCE_LANGS::LANG_CORNISH,
  RESOURCE_LANGS::LANG_WELSH,
  RESOURCE_LANGS::LANG_BRETON,
  RESOURCE_LANGS::LANG_INUKTITUT,
  RESOURCE_LANGS::LANG_IRISH,
  RESOURCE_LANGS::LANG_LOWER_SORBIAN,
  RESOURCE_LANGS::LANG_PULAR,
  RESOURCE_LANGS::LANG_QUECHUA,
  RESOURCE_LANGS::LANG_TAMAZIGHT,
  RESOURCE_LANGS::LANG_TIGRINYA,
  RESOURCE_LANGS::LANG_VALENCIAN,
};


static const RESOURCE_SUBLANGS resource_sublangs_array[] = {
  RESOURCE_SUBLANGS::SUBLANG_AFRIKAANS_SOUTH_AFRICA,
  RESOURCE_SUBLANGS::SUBLANG_ALBANIAN_ALBANIA,
  RESOURCE_SUBLANGS::SUBLANG_ALSATIAN_FRANCE,
  RESOURCE_SUBLANGS::SUBLANG_AMHARIC_ETHIOPIA,
  RESOURCE_SUBLANGS::SUBLANG_ARABIC_ALGERIA,
  RESOURCE_SUBLANGS::SUBLANG_ARABIC_BAHRAIN,
  RESOURCE_SUBLANGS::SUBLANG_ARABIC_EGYPT,
  RESOURCE_SUBLANGS::SUBLANG_ARABIC_IRAQ,
  RESOURCE_SUBLANGS::SUBLANG_ARABIC_JORDAN,
  RESOURCE_SUBLANGS::SUBLANG_ARABIC_KUWAIT,
  RESOURCE_SUBLANGS::SUBLANG_ARABIC_LEBANON,
  RESOURCE_SUBLANGS::SUBLANG_ARABIC_LIBYA,
  RESOURCE_SUBLANGS::SUBLANG_ARABIC_MOROCCO,
  RESOURCE_SUBLANGS::SUBLANG_ARABIC_OMAN,
  RESOURCE_SUBLANGS::SUBLANG_ARABIC_QATAR,
  RESOURCE_SUBLANGS::SUBLANG_ARABIC_SAUDI_ARABIA,
  RESOURCE_SUBLANGS::SUBLANG_ARABIC_SYRIA,
  RESOURCE_SUBLANGS::SUBLANG_ARABIC_TUNISIA,
  RESOURCE_SUBLANGS::SUBLANG_ARABIC_UAE,
  RESOURCE_SUBLANGS::SUBLANG_ARABIC_YEMEN,
  RESOURCE_SUBLANGS::SUBLANG_ARMENIAN_ARMENIA,
  RESOURCE_SUBLANGS::SUBLANG_ASSAMESE_INDIA,
  RESOURCE_SUBLANGS::SUBLANG_AZERI_CYRILLIC,
  RESOURCE_SUBLANGS::SUBLANG_AZERI_LATIN,
  RESOURCE_SUBLANGS::SUBLANG_BASHKIR_RUSSIA,
  RESOURCE_SUBLANGS::SUBLANG_BASQUE_BASQUE,
  RESOURCE_SUBLANGS::SUBLANG_BELARUSIAN_BELARUS,
  RESOURCE_SUBLANGS::SUBLANG_BANGLA_BANGLADESH,
  RESOURCE_SUBLANGS::SUBLANG_BANGLA_INDIA,
  RESOURCE_SUBLANGS::SUBLANG_BOSNIAN_BOSNIA_HERZEGOVINA_CYRILLIC,
  RESOURCE_SUBLANGS::SUBLANG_BOSNIAN_BOSNIA_HERZEGOVINA_LATIN,
  RESOURCE_SUBLANGS::SUBLANG_BRETON_FRANCE,
  RESOURCE_SUBLANGS::SUBLANG_BULGARIAN_BULGARIA,
  RESOURCE_SUBLANGS::SUBLANG_CATALAN_CATALAN,
  RESOURCE_SUBLANGS::SUBLANG_CHINESE_HONGKONG,
  RESOURCE_SUBLANGS::SUBLANG_CHINESE_MACAU,
  RESOURCE_SUBLANGS::SUBLANG_CHINESE_SIMPLIFIED,
  RESOURCE_SUBLANGS::SUBLANG_CHINESE_SINGAPORE,
  RESOURCE_SUBLANGS::SUBLANG_CHINESE_TRADITIONAL,
  RESOURCE_SUBLANGS::SUBLANG_CORSICAN_FRANCE,
  RESOURCE_SUBLANGS::SUBLANG_CROATIAN_BOSNIA_HERZEGOVINA_LATIN,
  RESOURCE_SUBLANGS::SUBLANG_CROATIAN_CROATIA,
  RESOURCE_SUBLANGS::SUBLANG_CUSTOM_DEFAULT,
  RESOURCE_SUBLANGS::SUBLANG_CUSTOM_UNSPECIFIED,
  RESOURCE_SUBLANGS::SUBLANG_CZECH_CZECH_REPUBLIC,
  RESOURCE_SUBLANGS::SUBLANG_DANISH_DENMARK,
  RESOURCE_SUBLANGS::SUBLANG_DARI_AFGHANISTAN,
  RESOURCE_SUBLANGS::SUBLANG_DEFAULT,
  RESOURCE_SUBLANGS::SUBLANG_DIVEHI_MALDIVES,
  RESOURCE_SUBLANGS::SUBLANG_DUTCH_BELGIAN,
  RESOURCE_SUBLANGS::SUBLANG_DUTCH,
  RESOURCE_SUBLANGS::SUBLANG_ENGLISH_AUS,
  RESOURCE_SUBLANGS::SUBLANG_ENGLISH_BELIZE,
  RESOURCE_SUBLANGS::SUBLANG_ENGLISH_CAN,
  RESOURCE_SUBLANGS::SUBLANG_ENGLISH_CARIBBEAN,
  RESOURCE_SUBLANGS::SUBLANG_ENGLISH_EIRE,
  RESOURCE_SUBLANGS::SUBLANG_ENGLISH_INDIA,
  RESOURCE_SUBLANGS::SUBLANG_ENGLISH_JAMAICA,
  RESOURCE_SUBLANGS::SUBLANG_ENGLISH_MALAYSIA,
  RESOURCE_SUBLANGS::SUBLANG_ENGLISH_NZ,
  RESOURCE_SUBLANGS::SUBLANG_ENGLISH_PHILIPPINES,
  RESOURCE_SUBLANGS::SUBLANG_ENGLISH_SINGAPORE,
  RESOURCE_SUBLANGS::SUBLANG_ENGLISH_SOUTH_AFRICA,
  RESOURCE_SUBLANGS::SUBLANG_ENGLISH_TRINIDAD,
  RESOURCE_SUBLANGS::SUBLANG_ENGLISH_UK,
  RESOURCE_SUBLANGS::SUBLANG_ENGLISH_US,
  RESOURCE_SUBLANGS::SUBLANG_ENGLISH_ZIMBABWE,
  RESOURCE_SUBLANGS::SUBLANG_ENGLISH_IRELAND,
  RESOURCE_SUBLANGS::SUBLANG_ESTONIAN_ESTONIA,
  RESOURCE_SUBLANGS::SUBLANG_FAEROESE_FAROE_ISLANDS,
  RESOURCE_SUBLANGS::SUBLANG_FILIPINO_PHILIPPINES,
  RESOURCE_SUBLANGS::SUBLANG_FINNISH_FINLAND,
  RESOURCE_SUBLANGS::SUBLANG_FRENCH_BELGIAN,
  RESOURCE_SUBLANGS::SUBLANG_FRENCH_CANADIAN,
  RESOURCE_SUBLANGS::SUBLANG_FRENCH_LUXEMBOURG,
  RESOURCE_SUBLANGS::SUBLANG_FRENCH_MONACO,
  RESOURCE_SUBLANGS::SUBLANG_FRENCH_SWISS,
  RESOURCE_SUBLANGS::SUBLANG_FRENCH,
  RESOURCE_SUBLANGS::SUBLANG_FRISIAN_NETHERLANDS,
  RESOURCE_SUBLANGS::SUBLANG_GALICIAN_GALICIAN,
  RESOURCE_SUBLANGS::SUBLANG_GEORGIAN_GEORGIA,
  RESOURCE_SUBLANGS::SUBLANG_GERMAN_AUSTRIAN,
  RESOURCE_SUBLANGS::SUBLANG_GERMAN_LIECHTENSTEIN,
  RESOURCE_SUBLANGS::SUBLANG_GERMAN_LUXEMBOURG,
  RESOURCE_SUBLANGS::SUBLANG_GERMAN_SWISS,
  RESOURCE_SUBLANGS::SUBLANG_GERMAN,
  RESOURCE_SUBLANGS::SUBLANG_GREEK_GREECE,
  RESOURCE_SUBLANGS::SUBLANG_GREENLANDIC_GREENLAND,
  RESOURCE_SUBLANGS::SUBLANG_GUJARATI_INDIA,
  RESOURCE_SUBLANGS::SUBLANG_HAUSA_NIGERIA_LATIN,
  RESOURCE_SUBLANGS::SUBLANG_HEBREW_ISRAEL,
  RESOURCE_SUBLANGS::SUBLANG_HINDI_INDIA,
  RESOURCE_SUBLANGS::SUBLANG_HUNGARIAN_HUNGARY,
  RESOURCE_SUBLANGS::SUBLANG_ICELANDIC_ICELAND,
  RESOURCE_SUBLANGS::SUBLANG_IGBO_NIGERIA,
  RESOURCE_SUBLANGS::SUBLANG_INDONESIAN_INDONESIA,
  RESOURCE_SUBLANGS::SUBLANG_INUKTITUT_CANADA_LATIN,
  RESOURCE_SUBLANGS::SUBLANG_INUKTITUT_CANADA,
  RESOURCE_SUBLANGS::SUBLANG_IRISH_IRELAND,
  RESOURCE_SUBLANGS::SUBLANG_ITALIAN_SWISS,
  RESOURCE_SUBLANGS::SUBLANG_ITALIAN,
  RESOURCE_SUBLANGS::SUBLANG_JAPANESE_JAPAN,
  RESOURCE_SUBLANGS::SUBLANG_KANNADA_INDIA,
  RESOURCE_SUBLANGS::SUBLANG_KASHMIRI_INDIA,
  RESOURCE_SUBLANGS::SUBLANG_KASHMIRI_SASIA,
  RESOURCE_SUBLANGS::SUBLANG_KAZAK_KAZAKHSTAN,
  RESOURCE_SUBLANGS::SUBLANG_KHMER_CAMBODIA,
  RESOURCE_SUBLANGS::SUBLANG_KICHE_GUATEMALA,
  RESOURCE_SUBLANGS::SUBLANG_KINYARWANDA_RWANDA,
  RESOURCE_SUBLANGS::SUBLANG_KONKANI_INDIA,
  RESOURCE_SUBLANGS::SUBLANG_KOREAN,
  RESOURCE_SUBLANGS::SUBLANG_KYRGYZ_KYRGYZSTAN,
  RESOURCE_SUBLANGS::SUBLANG_LAO_LAO,
  RESOURCE_SUBLANGS::SUBLANG_LATVIAN_LATVIA,
  RESOURCE_SUBLANGS::SUBLANG_LITHUANIAN_CLASSIC,
  RESOURCE_SUBLANGS::SUBLANG_LITHUANIAN,
  RESOURCE_SUBLANGS::SUBLANG_LOWER_SORBIAN_GERMANY,
  RESOURCE_SUBLANGS::SUBLANG_LUXEMBOURGISH_LUXEMBOURG,
  RESOURCE_SUBLANGS::SUBLANG_MACEDONIAN_MACEDONIA,
  RESOURCE_SUBLANGS::SUBLANG_MALAY_BRUNEI_DARUSSALAM,
  RESOURCE_SUBLANGS::SUBLANG_MALAY_MALAYSIA,
  RESOURCE_SUBLANGS::SUBLANG_MALAYALAM_INDIA,
  RESOURCE_SUBLANGS::SUBLANG_MALTESE_MALTA,
  RESOURCE_SUBLANGS::SUBLANG_MAORI_NEW_ZEALAND,
  RESOURCE_SUBLANGS::SUBLANG_MAPUDUNGUN_CHILE,
  RESOURCE_SUBLANGS::SUBLANG_MARATHI_INDIA,
  RESOURCE_SUBLANGS::SUBLANG_MOHAWK_MOHAWK,
  RESOURCE_SUBLANGS::SUBLANG_MONGOLIAN_CYRILLIC_MONGOLIA,
  RESOURCE_SUBLANGS::SUBLANG_MONGOLIAN_PRC,
  RESOURCE_SUBLANGS::SUBLANG_NEPALI_INDIA,
  RESOURCE_SUBLANGS::SUBLANG_NEPALI_NEPAL,
  RESOURCE_SUBLANGS::SUBLANG_NEUTRAL,
  RESOURCE_SUBLANGS::SUBLANG_NORWEGIAN_BOKMAL,
  RESOURCE_SUBLANGS::SUBLANG_NORWEGIAN_NYNORSK,
  RESOURCE_SUBLANGS::SUBLANG_OCCITAN_FRANCE,
  RESOURCE_SUBLANGS::SUBLANG_ORIYA_INDIA,
  RESOURCE_SUBLANGS::SUBLANG_PASHTO_AFGHANISTAN,
  RESOURCE_SUBLANGS::SUBLANG_PERSIAN_IRAN,
  RESOURCE_SUBLANGS::SUBLANG_POLISH_POLAND,
  RESOURCE_SUBLANGS::SUBLANG_PORTUGUESE_BRAZILIAN,
  RESOURCE_SUBLANGS::SUBLANG_PORTUGUESE,
  RESOURCE_SUBLANGS::SUBLANG_PUNJABI_INDIA,
  RESOURCE_SUBLANGS::SUBLANG_QUECHUA_BOLIVIA,
  RESOURCE_SUBLANGS::SUBLANG_QUECHUA_ECUADOR,
  RESOURCE_SUBLANGS::SUBLANG_QUECHUA_PERU,
  RESOURCE_SUBLANGS::SUBLANG_ROMANIAN_ROMANIA,
  RESOURCE_SUBLANGS::SUBLANG_ROMANSH_SWITZERLAND,
  RESOURCE_SUBLANGS::SUBLANG_RUSSIAN_RUSSIA,
  RESOURCE_SUBLANGS::SUBLANG_SAMI_INARI_FINLAND,
  RESOURCE_SUBLANGS::SUBLANG_SAMI_LULE_NORWAY,
  RESOURCE_SUBLANGS::SUBLANG_SAMI_LULE_SWEDEN,
  RESOURCE_SUBLANGS::SUBLANG_SAMI_NORTHERN_FINLAND,
  RESOURCE_SUBLANGS::SUBLANG_SAMI_NORTHERN_NORWAY,
  RESOURCE_SUBLANGS::SUBLANG_SAMI_NORTHERN_SWEDEN,
  RESOURCE_SUBLANGS::SUBLANG_SAMI_SKOLT_FINLAND,
  RESOURCE_SUBLANGS::SUBLANG_SAMI_SOUTHERN_NORWAY,
  RESOURCE_SUBLANGS::SUBLANG_SAMI_SOUTHERN_SWEDEN,
  RESOURCE_SUBLANGS::SUBLANG_SANSKRIT_INDIA,
  RESOURCE_SUBLANGS::SUBLANG_SERBIAN_BOSNIA_HERZEGOVINA_CYRILLIC,
  RESOURCE_SUBLANGS::SUBLANG_SERBIAN_BOSNIA_HERZEGOVINA_LATIN,
  RESOURCE_SUBLANGS::SUBLANG_SERBIAN_CROATIA,
  RESOURCE_SUBLANGS::SUBLANG_SERBIAN_CYRILLIC,
  RESOURCE_SUBLANGS::SUBLANG_SERBIAN_LATIN,
  RESOURCE_SUBLANGS::SUBLANG_SINDHI_AFGHANISTAN,
  RESOURCE_SUBLANGS::SUBLANG_SINDHI_INDIA,
  RESOURCE_SUBLANGS::SUBLANG_SINDHI_PAKISTAN,
  RESOURCE_SUBLANGS::SUBLANG_SINHALESE_SRI_LANKA,
  RESOURCE_SUBLANGS::SUBLANG_SLOVAK_SLOVAKIA,
  RESOURCE_SUBLANGS::SUBLANG_SLOVENIAN_SLOVENIA,
  RESOURCE_SUBLANGS::SUBLANG_SOTHO_NORTHERN_SOUTH_AFRICA,
  RESOURCE_SUBLANGS::SUBLANG_SPANISH_ARGENTINA,
  RESOURCE_SUBLANGS::SUBLANG_SPANISH_BOLIVIA,
  RESOURCE_SUBLANGS::SUBLANG_SPANISH_CHILE,
  RESOURCE_SUBLANGS::SUBLANG_SPANISH_COLOMBIA,
  RESOURCE_SUBLANGS::SUBLANG_SPANISH_COSTA_RICA,
  RESOURCE_SUBLANGS::SUBLANG_SPANISH_DOMINICAN_REPUBLIC,
  RESOURCE_SUBLANGS::SUBLANG_SPANISH_ECUADOR,
  RESOURCE_SUBLANGS::SUBLANG_SPANISH_EL_SALVADOR,
  RESOURCE_SUBLANGS::SUBLANG_SPANISH_GUATEMALA,
  RESOURCE_SUBLANGS::SUBLANG_SPANISH_HONDURAS,
  RESOURCE_SUBLANGS::SUBLANG_SPANISH_MEXICAN,
  RESOURCE_SUBLANGS::SUBLANG_SPANISH_MODERN,
  RESOURCE_SUBLANGS::SUBLANG_SPANISH_NICARAGUA,
  RESOURCE_SUBLANGS::SUBLANG_SPANISH_PANAMA,
  RESOURCE_SUBLANGS::SUBLANG_SPANISH_PARAGUAY,
  RESOURCE_SUBLANGS::SUBLANG_SPANISH_PERU,
  RESOURCE_SUBLANGS::SUBLANG_SPANISH_PUERTO_RICO,
  RESOURCE_SUBLANGS::SUBLANG_SPANISH_URUGUAY,
  RESOURCE_SUBLANGS::SUBLANG_SPANISH_US,
  RESOURCE_SUBLANGS::SUBLANG_SPANISH_VENEZUELA,
  RESOURCE_SUBLANGS::SUBLANG_SPANISH,
  RESOURCE_SUBLANGS::SUBLANG_SWAHILI_KENYA,
  RESOURCE_SUBLANGS::SUBLANG_SWEDISH_FINLAND,
  RESOURCE_SUBLANGS::SUBLANG_SWEDISH,
  RESOURCE_SUBLANGS::SUBLANG_SYRIAC_SYRIA,
  RESOURCE_SUBLANGS::SUBLANG_SYS_DEFAULT,
  RESOURCE_SUBLANGS::SUBLANG_TAJIK_TAJIKISTAN,
  RESOURCE_SUBLANGS::SUBLANG_TAMAZIGHT_ALGERIA_LATIN,
  RESOURCE_SUBLANGS::SUBLANG_TAMIL_INDIA,
  RESOURCE_SUBLANGS::SUBLANG_TATAR_RUSSIA,
  RESOURCE_SUBLANGS::SUBLANG_TELUGU_INDIA,
  RESOURCE_SUBLANGS::SUBLANG_THAI_THAILAND,
  RESOURCE_SUBLANGS::SUBLANG_TIBETAN_PRC,
  RESOURCE_SUBLANGS::SUBLANG_TIGRIGNA_ERITREA,
  RESOURCE_SUBLANGS::SUBLANG_TSWANA_SOUTH_AFRICA,
  RESOURCE_SUBLANGS::SUBLANG_TURKISH_TURKEY,
  RESOURCE_SUBLANGS::SUBLANG_TURKMEN_TURKMENISTAN,
  RESOURCE_SUBLANGS::SUBLANG_UI_CUSTOM_DEFAULT,
  RESOURCE_SUBLANGS::SUBLANG_UIGHUR_PRC,
  RESOURCE_SUBLANGS::SUBLANG_UKRAINIAN_UKRAINE,
  RESOURCE_SUBLANGS::SUBLANG_UPPER_SORBIAN_GERMANY,
  RESOURCE_SUBLANGS::SUBLANG_URDU_INDIA,
  RESOURCE_SUBLANGS::SUBLANG_URDU_PAKISTAN,
  RESOURCE_SUBLANGS::SUBLANG_UZBEK_CYRILLIC,
  RESOURCE_SUBLANGS::SUBLANG_UZBEK_LATIN,
  RESOURCE_SUBLANGS::SUBLANG_VIETNAMESE_VIETNAM,
  RESOURCE_SUBLANGS::SUBLANG_WELSH_UNITED_KINGDOM,
  RESOURCE_SUBLANGS::SUBLANG_WOLOF_SENEGAL,
  RESOURCE_SUBLANGS::SUBLANG_XHOSA_SOUTH_AFRICA,
  RESOURCE_SUBLANGS::SUBLANG_YAKUT_RUSSIA,
  RESOURCE_SUBLANGS::SUBLANG_YI_PRC,
  RESOURCE_SUBLANGS::SUBLANG_YORUBA_NIGERIA,
  RESOURCE_SUBLANGS::SUBLANG_ZULU_SOUTH_AFRICA,
};


static const GUARD_CF_FLAGS guard_cf_flags_array[] = {
  GUARD_CF_FLAGS::GCF_INSTRUMENTED,
  GUARD_CF_FLAGS::GCF_W_INSTRUMENTED,
  GUARD_CF_FLAGS::GCF_FUNCTION_TABLE_PRESENT,
  GUARD_CF_FLAGS::GCF_EXPORT_SUPPRESSION_INFO_PRESENT,
  GUARD_CF_FLAGS::GCF_ENABLE_EXPORT_SUPPRESSION,
  GUARD_CF_FLAGS::GCF_LONGJUMP_TABLE_PRESENT,
  GUARD_CF_FLAGS::GRF_INSTRUMENTED,
  GUARD_CF_FLAGS::GRF_ENABLE,
  GUARD_CF_FLAGS::GRF_STRICT,
};

}
}

ENABLE_BITMASK_OPERATORS(LIEF::PE::SECTION_CHARACTERISTICS)
ENABLE_BITMASK_OPERATORS(LIEF::PE::DLL_CHARACTERISTICS)
ENABLE_BITMASK_OPERATORS(LIEF::PE::HEADER_CHARACTERISTICS)
ENABLE_BITMASK_OPERATORS(LIEF::PE::GUARD_CF_FLAGS)
ENABLE_BITMASK_OPERATORS(LIEF::PE::ACCELERATOR_FLAGS)
#endif
