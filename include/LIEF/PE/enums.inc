
enum MACHINE_TYPES {
  MT_Invalid = 0xffff,
  IMAGE_FILE_MACHINE_UNKNOWN   = 0x0,
  IMAGE_FILE_MACHINE_AM33      = 0x13,   /**< Matsushita AM33               */
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
  IMAGE_FILE_MACHINE_SH3       = 0x1A2,  /**< Hitachi SH3                    */
  IMAGE_FILE_MACHINE_SH3DSP    = 0x1A3,  /**< Hitachi SH3 DSP                */
  IMAGE_FILE_MACHINE_SH4       = 0x1A6,  /**< Hitachi SH4                    */
  IMAGE_FILE_MACHINE_SH5       = 0x1A8,  /**< Hitachi SH5                    */
  IMAGE_FILE_MACHINE_THUMB     = 0x1C2,  /**< ARM or Thumb                   */
  IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169   /**< MIPS little-endian WCE v2      */
};

enum SYMBOL_SECTION_NUMBER {
  IMAGE_SYM_DEBUG     = -2,
  IMAGE_SYM_ABSOLUTE  = -1,
  IMAGE_SYM_UNDEFINED = 0
};


enum HEADER_CHARACTERISTICS {
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
enum SYMBOL_STORAGE_CLASS {
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


enum SYMBOL_BASE_TYPES {
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

enum SYMBOL_COMPLEX_TYPES {
  IMAGE_SYM_DTYPE_NULL     = 0, ///< No complex type; simple scalar variable.
  IMAGE_SYM_DTYPE_POINTER  = 1, ///< A pointer to base type.
  IMAGE_SYM_DTYPE_FUNCTION = 2, ///< A function that returns a base type.
  IMAGE_SYM_DTYPE_ARRAY    = 3, ///< An array of base type.
  SCT_COMPLEX_TYPE_SHIFT   = 4  ///< Type is formed as (base + (derived << SCT_COMPLEX_TYPE_SHIFT))
};

enum AuxSymbolType {
  IMAGE_AUX_SYMBOL_TYPE_TOKEN_DEF = 1
};


enum RELOCATIONS_BASE_TYPES {
  IMAGE_REL_BASED_ABSOLUTE       = 0,
  IMAGE_REL_BASED_HIGH           = 1,
  IMAGE_REL_BASED_LOW            = 2,
  IMAGE_REL_BASED_HIGHLOW        = 3,
  IMAGE_REL_BASED_HIGHADJ        = 4,
  IMAGE_REL_BASED_MIPS_JMPADDR   = 5,
  IMAGE_REL_BASED_SECTION        = 6,
  IMAGE_REL_BASED_REL            = 7,
  IMAGE_REL_BASED_MIPS_JMPADDR16 = 9,
  IMAGE_REL_BASED_IA64_IMM64     = 9,
  IMAGE_REL_BASED_DIR64          = 10,
  IMAGE_REL_BASED_HIGH3ADJ       = 11,
};

enum RELOCATIONS_I386 {
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

enum RELOCATIONS_AMD64 {
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

enum RELOCATIONS_ARM {
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
enum WeakExternalCharacteristics {
  IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY = 1,
  IMAGE_WEAK_EXTERN_SEARCH_LIBRARY   = 2,
  IMAGE_WEAK_EXTERN_SEARCH_ALIAS     = 3
};


enum DATA_DIRECTORY {
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

  NUM_DATA_DIRECTORIES    = 15
};


enum SUBSYSTEM {
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

enum DLL_CHARACTERISTICS {
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


enum DEBUG_TYPES {
  IMAGE_DEBUG_TYPE_UNKNOWN       = 0,
  IMAGE_DEBUG_TYPE_COFF          = 1,
  IMAGE_DEBUG_TYPE_CODEVIEW      = 2,
  IMAGE_DEBUG_TYPE_FPO           = 3,
  IMAGE_DEBUG_TYPE_MISC          = 4,
  IMAGE_DEBUG_TYPE_EXCEPTION     = 5,
  IMAGE_DEBUG_TYPE_FIXUP         = 6,
  IMAGE_DEBUG_TYPE_OMAP_TO_SRC   = 7,
  IMAGE_DEBUG_TYPE_OMAP_FROM_SRC = 8,
  IMAGE_DEBUG_TYPE_BORLAND       = 9,
  IMAGE_DEBUG_TYPE_CLSID         = 11
};

enum ImportType {
  IMPORT_CODE  = 0,
  IMPORT_DATA  = 1,
  IMPORT_CONST = 2
};


enum ImportNameType {
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


enum CodeViewIdentifiers {
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
enum RESOURCE_TYPES {
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
  GROUP_ICON   = 13,
  VERSION      = 14,
  DLGINCLUDE   = 15,
  PLUGPLAY     = 16,
  VXD          = 17,
  ANICURSOR    = 18,
  ANIICON      = 19,
  HTML         = 20,
  MANIFEST     = 21
};


enum SECTION_CHARACTERISTICS {
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
  IMAGE_SCN_MEM_PURGEABLE          = 0x00020000,
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

