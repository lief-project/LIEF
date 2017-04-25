
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

//! @brief From https://msdn.microsoft.com/en-us/library/ms648009(v=vs.85).aspx
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

enum RESOURCE_LANGS {
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
  LANG_BENGALI        = 0x45,
  LANG_BULGARIAN      = 0x02,
  LANG_CATALAN        = 0x03,
  LANG_CHINESE        = 0x04,
  LANG_CROATIAN       = 0x1a,
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
  LANG_SAAMI          = 0x3b,
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
  LANG_BRETON         = 0x93
};


enum RESOURCE_SUBLANGS {
  SUBLANG_NEUTRAL                    =  0x00,
  SUBLANG_DEFAULT                    =  0x01,
  SUBLANG_SYS_DEFAULT                =  0x02,
  SUBLANG_ARABIC_SAUDI_ARABIA        =  0x01,
  SUBLANG_ARABIC_IRAQ                =  0x02,
  SUBLANG_ARABIC_EGYPT               =  0x03,
  SUBLANG_ARABIC_LIBYA               =  0x04,
  SUBLANG_ARABIC_ALGERIA             =  0x05,
  SUBLANG_ARABIC_MOROCCO             =  0x06,
  SUBLANG_ARABIC_TUNISIA             =  0x07,
  SUBLANG_ARABIC_OMAN                =  0x08,
  SUBLANG_ARABIC_YEMEN               =  0x09,
  SUBLANG_ARABIC_SYRIA               =  0x0a,
  SUBLANG_ARABIC_JORDAN              =  0x0b,
  SUBLANG_ARABIC_LEBANON             =  0x0c,
  SUBLANG_ARABIC_KUWAIT              =  0x0d,
  SUBLANG_ARABIC_UAE                 =  0x0e,
  SUBLANG_ARABIC_BAHRAIN             =  0x0f,
  SUBLANG_ARABIC_QATAR               =  0x10,
  SUBLANG_AZERI_LATIN                =  0x01,
  SUBLANG_AZERI_CYRILLIC             =  0x02,
  SUBLANG_CHINESE_TRADITIONAL        =  0x01,
  SUBLANG_CHINESE_SIMPLIFIED         =  0x02,
  SUBLANG_CHINESE_HONGKONG           =  0x03,
  SUBLANG_CHINESE_SINGAPORE          =  0x04,
  SUBLANG_CHINESE_MACAU              =  0x05,
  SUBLANG_DUTCH                      =  0x01,
  SUBLANG_DUTCH_BELGIAN              =  0x02,
  SUBLANG_ENGLISH_US                 =  0x01,
  SUBLANG_ENGLISH_UK                 =  0x02,
  SUBLANG_ENGLISH_AUS                =  0x03,
  SUBLANG_ENGLISH_CAN                =  0x04,
  SUBLANG_ENGLISH_NZ                 =  0x05,
  SUBLANG_ENGLISH_EIRE               =  0x06,
  SUBLANG_ENGLISH_SOUTH_AFRICA       =  0x07,
  SUBLANG_ENGLISH_JAMAICA            =  0x08,
  SUBLANG_ENGLISH_CARIBBEAN          =  0x09,
  SUBLANG_ENGLISH_BELIZE             =  0x0a,
  SUBLANG_ENGLISH_TRINIDAD           =  0x0b,
  SUBLANG_ENGLISH_ZIMBABWE           =  0x0c,
  SUBLANG_ENGLISH_PHILIPPINES        =  0x0d,
  SUBLANG_FRENCH                     =  0x01,
  SUBLANG_FRENCH_BELGIAN             =  0x02,
  SUBLANG_FRENCH_CANADIAN            =  0x03,
  SUBLANG_FRENCH_SWISS               =  0x04,
  SUBLANG_FRENCH_LUXEMBOURG          =  0x05,
  SUBLANG_FRENCH_MONACO              =  0x06,
  SUBLANG_GERMAN                     =  0x01,
  SUBLANG_GERMAN_SWISS               =  0x02,
  SUBLANG_GERMAN_AUSTRIAN            =  0x03,
  SUBLANG_GERMAN_LUXEMBOURG          =  0x04,
  SUBLANG_GERMAN_LIECHTENSTEIN       =  0x05,
  SUBLANG_ITALIAN                    =  0x01,
  SUBLANG_ITALIAN_SWISS              =  0x02,
  SUBLANG_KASHMIRI_SASIA             =  0x02,
  SUBLANG_KASHMIRI_INDIA             =  0x02,
  SUBLANG_KOREAN                     =  0x01,
  SUBLANG_LITHUANIAN                 =  0x01,
  SUBLANG_MALAY_MALAYSIA             =  0x01,
  SUBLANG_MALAY_BRUNEI_DARUSSALAM    =  0x02,
  SUBLANG_NEPALI_INDIA               =  0x02,
  SUBLANG_NORWEGIAN_BOKMAL           =  0x01,
  SUBLANG_NORWEGIAN_NYNORSK          =  0x02,
  SUBLANG_PORTUGUESE                 =  0x02,
  SUBLANG_PORTUGUESE_BRAZILIAN       =  0x01,
  SUBLANG_SERBIAN_LATIN              =  0x02,
  SUBLANG_SERBIAN_CYRILLIC           =  0x03,
  SUBLANG_SPANISH                    =  0x01,
  SUBLANG_SPANISH_MEXICAN            =  0x02,
  SUBLANG_SPANISH_MODERN             =  0x03,
  SUBLANG_SPANISH_GUATEMALA          =  0x04,
  SUBLANG_SPANISH_COSTA_RICA         =  0x05,
  SUBLANG_SPANISH_PANAMA             =  0x06,
  SUBLANG_SPANISH_DOMINICAN_REPUBLIC =  0x07,
  SUBLANG_SPANISH_VENEZUELA          =  0x08,
  SUBLANG_SPANISH_COLOMBIA           =  0x09,
  SUBLANG_SPANISH_PERU               =  0x0a,
  SUBLANG_SPANISH_ARGENTINA          =  0x0b,
  SUBLANG_SPANISH_ECUADOR            =  0x0c,
  SUBLANG_SPANISH_CHILE              =  0x0d,
  SUBLANG_SPANISH_URUGUAY            =  0x0e,
  SUBLANG_SPANISH_PARAGUAY           =  0x0f,
  SUBLANG_SPANISH_BOLIVIA            =  0x10,
  SUBLANG_SPANISH_EL_SALVADOR        =  0x11,
  SUBLANG_SPANISH_HONDURAS           =  0x12,
  SUBLANG_SPANISH_NICARAGUA          =  0x13,
  SUBLANG_SPANISH_PUERTO_RICO        =  0x14,
  SUBLANG_SWEDISH                    =  0x01,
  SUBLANG_SWEDISH_FINLAND            =  0x02,
  SUBLANG_URDU_PAKISTAN              =  0x01,
  SUBLANG_URDU_INDIA                 =  0x02,
  SUBLANG_UZBEK_LATIN                =  0x01,
  SUBLANG_UZBEK_CYRILLIC             =  0x02,
  SUBLANG_DUTCH_SURINAM              =  0x03,
  SUBLANG_ROMANIAN                   =  0x01,
  SUBLANG_ROMANIAN_MOLDAVIA          =  0x02,
  SUBLANG_RUSSIAN                    =  0x01,
  SUBLANG_RUSSIAN_MOLDAVIA           =  0x02,
  SUBLANG_CROATIAN                   =  0x01,
  SUBLANG_LITHUANIAN_CLASSIC         =  0x02,
  SUBLANG_GAELIC                     =  0x01,
  SUBLANG_GAELIC_SCOTTISH            =  0x02,
  SUBLANG_GAELIC_MANX                =  0x03,
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

//! @brief From https://msdn.microsoft.com/en-us/library/ff700543.aspx
enum EXTENDED_WINDOW_STYLES {
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

//! @brief From: https://msdn.microsoft.com/en-us/library/ms632600.aspx
enum WINDOW_STYLES {
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


//! @brief From https://msdn.microsoft.com/en-us/library/ff729172.aspx
enum DIALOG_BOX_STYLES {
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
  DS_SHELLFONT     = DS_SETFONT | DS_FIXEDSYS,
};

enum FIXED_VERSION_OS {
  VOS_UNKNOWN       = 0x00000000L,
  VOS_DOS           = 0x00010000L,
  VOS_NT            = 0x00040000L,
  VOS__WINDOWS16    = 0x00000001L,
  VOS__WINDOWS32    = 0x00000004L,
  VOS_OS216         = 0x00020000L,
  VOS_OS232         = 0x00030000L,
  VOS__PM16         = 0x00000002L,
  VOS__PM32         = 0x00000003L,
  VOS_DOS_WINDOWS16 = VOS_DOS   | VOS__WINDOWS16,
  VOS_DOS_WINDOWS32 = VOS_DOS   | VOS__WINDOWS32,
  VOS_NT_WINDOWS32  = VOS_NT    | VOS__WINDOWS32,
  VOS_OS216_PM16    = VOS_OS216 | VOS__PM16,
  VOS_OS232_PM32    = VOS_OS232 | VOS__PM32,
};


enum FIXED_VERSION_FILE_FLAGS {
  VS_FF_DEBUG        = 0x00000001L,
  VS_FF_INFOINFERRED = 0x00000010L,
  VS_FF_PATCHED      = 0x00000004L,
  VS_FF_PRERELEASE   = 0x00000002L,
  VS_FF_PRIVATEBUILD = 0x00000008L,
  VS_FF_SPECIALBUILD = 0x00000020L,
};


enum FIXED_VERSION_FILE_TYPES {
  VFT_APP        = 0x00000001L,
  VFT_DLL        = 0x00000002L,
  VFT_DRV        = 0x00000003L,
  VFT_FONT       = 0x00000004L,
  VFT_STATIC_LIB = 0x00000007L,
  VFT_UNKNOWN    = 0x00000000L,
  VFT_VXD        = 0x00000005L,
};


enum FIXED_VERSION_FILE_SUB_TYPES {
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

//! @brief Code page from http://msdn.microsoft.com/en-us/library/ms776446(VS.85).aspx
enum CODE_PAGES {
  CP_IBM037                  = 37,		/**< IBM EBCDIC US-Canada */
  CP_IBM437                  = 437,		/**< OEM United States */
  CP_IBM500                  = 500,		/**< IBM EBCDIC International */
  CP_ASMO_708                = 708,		/**< Arabic (ASMO 708) */
  CP_DOS_720                 = 720,		/**< Arabic (Transparent ASMO); Arabic (DOS) */
  CP_IBM737                  = 737,		/**< OEM Greek (formerly 437G); Greek (DOS) */
  CP_IBM775                  = 775,		/**< OEM Baltic; Baltic (DOS) */
  CP_IBM850                  = 850,		/**< OEM Multilingual Latin 1; Western European (DOS) */
  CP_IBM852                  = 852,		/**< OEM Latin 2; Central European (DOS) */
  CP_IBM855                  = 855,		/**< OEM Cyrillic (primarily Russian) */
  CP_IBM857                  = 857,		/**< OEM Turkish; Turkish (DOS) */
  CP_IBM00858                = 858,		/**< OEM Multilingual Latin 1 + Euro symbol */
  CP_IBM860                  = 860,		/**< OEM Portuguese; Portuguese (DOS) */
  CP_IBM861                  = 861,		/**< OEM Icelandic; Icelandic (DOS) */
  CP_DOS_862                 = 862,		/**< OEM Hebrew; Hebrew (DOS) */
  CP_IBM863                  = 863,		/**< OEM French Canadian; French Canadian (DOS) */
  CP_IBM864                  = 864,		/**< OEM Arabic; Arabic (864) */
  CP_IBM865                  = 865,		/**< OEM Nordic; Nordic (DOS) */
  CP_CP866                   = 866,		/**< OEM Russian; Cyrillic (DOS) */
  CP_IBM869                  = 869,		/**< OEM Modern Greek; Greek, Modern (DOS) */
  CP_IBM870                  = 870,		/**< IBM EBCDIC Multilingual/ROECE (Latin 2); IBM EBCDIC Multilingual Latin 2 */
  CP_WINDOWS_874             = 874,		/**< ANSI/OEM Thai (same as 28605, ISO 8859-15); Thai (Windows) */
  CP_CP875                   = 875,		/**< IBM EBCDIC Greek Modern */
  CP_SHIFT_JIS               = 932,		/**< ANSI/OEM Japanese; Japanese (Shift-JIS) */
  CP_GB2312                  = 936,		/**< ANSI/OEM Simplified Chinese (PRC, Singapore); Chinese Simplified (GB2312) */
  CP_KS_C_5601_1987          = 949,		/**< ANSI/OEM Korean (Unified Hangul Code) */
  CP_BIG5                    = 950,		/**< ANSI/OEM Traditional Chinese (Taiwan; Hong Kong SAR, PRC); Chinese Traditional (Big5) */
  CP_IBM1026                 = 1026,	/**< IBM EBCDIC Turkish (Latin 5) */
  CP_IBM01047                = 1047,	/**< IBM EBCDIC Latin 1/Open System */
  CP_IBM01140                = 1140,	/**< IBM EBCDIC US-Canada (037 + Euro symbol); IBM EBCDIC (US-Canada-Euro) */
  CP_IBM01141                = 1141,	/**< IBM EBCDIC Germany (20273 + Euro symbol); IBM EBCDIC (Germany-Euro) */
  CP_IBM01142                = 1142,	/**< IBM EBCDIC Denmark-Norway (20277 + Euro symbol); IBM EBCDIC (Denmark-Norway-Euro) */
  CP_IBM01143                = 1143,	/**< IBM EBCDIC Finland-Sweden (20278 + Euro symbol); IBM EBCDIC (Finland-Sweden-Euro) */
  CP_IBM01144                = 1144,	/**< IBM EBCDIC Italy (20280 + Euro symbol); IBM EBCDIC (Italy-Euro) */
  CP_IBM01145                = 1145,	/**< IBM EBCDIC Latin America-Spain (20284 + Euro symbol); IBM EBCDIC (Spain-Euro) */
  CP_IBM01146                = 1146,	/**< IBM EBCDIC United Kingdom (20285 + Euro symbol); IBM EBCDIC (UK-Euro) */
  CP_IBM01147                = 1147,	/**< IBM EBCDIC France (20297 + Euro symbol); IBM EBCDIC (France-Euro) */
  CP_IBM01148                = 1148,	/**< IBM EBCDIC International (500 + Euro symbol); IBM EBCDIC (International-Euro) */
  CP_IBM01149                = 1149,	/**< IBM EBCDIC Icelandic (20871 + Euro symbol); IBM EBCDIC (Icelandic-Euro) */
  CP_UTF_16                  = 1200,	/**< Unicode UTF-16, little endian byte order (BMP of ISO 10646); available only to managed applications */
  CP_UNICODEFFFE             = 1201,	/**< Unicode UTF-16, big endian byte order; available only to managed applications */
  CP_WINDOWS_1250            = 1250,	/**< ANSI Central European; Central European (Windows) */
  CP_WINDOWS_1251            = 1251,	/**< ANSI Cyrillic; Cyrillic (Windows) */
  CP_WINDOWS_1252            = 1252,	/**< ANSI Latin 1; Western European (Windows) */
  CP_WINDOWS_1253            = 1253,	/**< ANSI Greek; Greek (Windows) */
  CP_WINDOWS_1254            = 1254,	/**< ANSI Turkish; Turkish (Windows) */
  CP_WINDOWS_1255            = 1255,	/**< ANSI Hebrew; Hebrew (Windows) */
  CP_WINDOWS_1256            = 1256,	/**< ANSI Arabic; Arabic (Windows) */
  CP_WINDOWS_1257            = 1257,	/**< ANSI Baltic; Baltic (Windows) */
  CP_WINDOWS_1258            = 1258,	/**< ANSI/OEM Vietnamese; Vietnamese (Windows) */
  CP_JOHAB                   = 1361,	/**< Korean (Johab) */
  CP_MACINTOSH               = 10000,	/**< MAC Roman; Western European (Mac) */
  CP_X_MAC_JAPANESE          = 10001,	/**< Japanese (Mac) */
  CP_X_MAC_CHINESETRAD       = 10002,	/**< MAC Traditional Chinese (Big5); Chinese Traditional (Mac) */
  CP_X_MAC_KOREAN            = 10003,	/**< Korean (Mac) */
  CP_X_MAC_ARABIC            = 10004,	/**< Arabic (Mac) */
  CP_X_MAC_HEBREW            = 10005,	/**< Hebrew (Mac) */
  CP_X_MAC_GREEK             = 10006,	/**< Greek (Mac) */
  CP_X_MAC_CYRILLIC          = 10007,	/**< Cyrillic (Mac) */
  CP_X_MAC_CHINESESIMP       = 10008,	/**< MAC Simplified Chinese (GB 2312); Chinese Simplified (Mac) */
  CP_X_MAC_ROMANIAN          = 10010,	/**< Romanian (Mac) */
  CP_X_MAC_UKRAINIAN         = 10017,	/**< Ukrainian (Mac) */
  CP_X_MAC_THAI              = 10021,	/**< Thai (Mac) */
  CP_X_MAC_CE                = 10029,	/**< MAC Latin 2; Central European (Mac) */
  CP_X_MAC_ICELANDIC         = 10079,	/**< Icelandic (Mac) */
  CP_X_MAC_TURKISH           = 10081,	/**< Turkish (Mac) */
  CP_X_MAC_CROATIAN          = 10082,	/**< Croatian (Mac) */
  CP_UTF_32                  = 12000,	/**< Unicode UTF-32, little endian byte order; available only to managed applications */
  CP_UTF_32BE                = 12001,	/**< Unicode UTF-32, big endian byte order; available only to managed applications */
  CP_X_CHINESE_CNS           = 20000,	/**< CNS Taiwan; Chinese Traditional (CNS) */
  CP_X_CP20001               = 20001,	/**< TCA Taiwan */
  CP_X_CHINESE_ETEN          = 20002,	/**< Eten Taiwan; Chinese Traditional (Eten) */
  CP_X_CP20003               = 20003,	/**< IBM5550 Taiwan */
  CP_X_CP20004               = 20004,	/**< TeleText Taiwan */
  CP_X_CP20005               = 20005,	/**< Wang Taiwan */
  CP_X_IA5                   = 20105,	/**< IA5 (IRV International Alphabet No. 5, 7-bit); Western European (IA5) */
  CP_X_IA5_GERMAN            = 20106,	/**< IA5 German (7-bit) */
  CP_X_IA5_SWEDISH           = 20107,	/**< IA5 Swedish (7-bit) */
  CP_X_IA5_NORWEGIAN         = 20108,	/**< IA5 Norwegian (7-bit) */
  CP_US_ASCII                = 20127,	/**< US-ASCII (7-bit) */
  CP_X_CP20261               = 20261,	/**< T.61 */
  CP_X_CP20269               = 20269,	/**< ISO 6937 Non-Spacing Accent */
  CP_IBM273                  = 20273,	/**< IBM EBCDIC Germany */
  CP_IBM277                  = 20277,	/**< IBM EBCDIC Denmark-Norway */
  CP_IBM278                  = 20278,	/**< IBM EBCDIC Finland-Sweden */
  CP_IBM280                  = 20280,	/**< IBM EBCDIC Italy */
  CP_IBM284                  = 20284,	/**< IBM EBCDIC Latin America-Spain */
  CP_IBM285                  = 20285,	/**< IBM EBCDIC United Kingdom */
  CP_IBM290                  = 20290,	/**< IBM EBCDIC Japanese Katakana Extended */
  CP_IBM297                  = 20297,	/**< IBM EBCDIC France */
  CP_IBM420                  = 20420,	/**< IBM EBCDIC Arabic */
  CP_IBM423                  = 20423,	/**< IBM EBCDIC Greek */
  CP_IBM424                  = 20424,	/**< IBM EBCDIC Hebrew */
  CP_X_EBCDIC_KOREANEXTENDED = 20833,	/**< IBM EBCDIC Korean Extended */
  CP_IBM_THAI                = 20838,	/**< IBM EBCDIC Thai */
  CP_KOI8_R                  = 20866,	/**< Russian (KOI8-R); Cyrillic (KOI8-R) */
  CP_IBM871                  = 20871,	/**< IBM EBCDIC Icelandic */
  CP_IBM880                  = 20880,	/**< IBM EBCDIC Cyrillic Russian */
  CP_IBM905                  = 20905,	/**< IBM EBCDIC Turkish */
  CP_IBM00924                = 20924,	/**< IBM EBCDIC Latin 1/Open System (1047 + Euro symbol) */
  CP_EUC_JP_JIS              = 20932,	/**< Japanese (JIS 0208-1990 and 0121-1990) */
  CP_X_CP20936               = 20936,	/**< Simplified Chinese (GB2312); Chinese Simplified (GB2312-80) */
  CP_X_CP20949               = 20949,	/**< Korean Wansung */
  CP_CP1025                  = 21025,	/**< IBM EBCDIC Cyrillic Serbian-Bulgarian */
  CP_KOI8_U                  = 21866,	/**< Ukrainian (KOI8-U); Cyrillic (KOI8-U) */
  CP_ISO_8859_1              = 28591,	/**< ISO 8859-1 Latin 1; Western European (ISO) */
  CP_ISO_8859_2              = 28592,	/**< ISO 8859-2 Central European; Central European (ISO) */
  CP_ISO_8859_3              = 28593,	/**< ISO 8859-3 Latin 3 */
  CP_ISO_8859_4              = 28594,	/**< ISO 8859-4 Baltic */
  CP_ISO_8859_5              = 28595,	/**< ISO 8859-5 Cyrillic */
  CP_ISO_8859_6              = 28596,	/**< ISO 8859-6 Arabic */
  CP_ISO_8859_7              = 28597,	/**< ISO 8859-7 Greek */
  CP_ISO_8859_8              = 28598,	/**< ISO 8859-8 Hebrew; Hebrew (ISO-Visual) */
  CP_ISO_8859_9              = 28599,	/**< ISO 8859-9 Turkish */
  CP_ISO_8859_13             = 28603,	/**< ISO 8859-13 Estonian */
  CP_ISO_8859_15             = 28605,	/**< ISO 8859-15 Latin 9 */
  CP_X_EUROPA                = 29001,	/**< Europa 3 */
  CP_ISO_8859_8_I            = 38598,	/**< ISO 8859-8 Hebrew; Hebrew (ISO-Logical) */
  CP_ISO_2022_JP             = 50220,	/**< ISO 2022 Japanese with no halfwidth Katakana; Japanese (JIS) */
  CP_CSISO2022JP             = 50221,	/**< ISO 2022 Japanese with halfwidth Katakana; Japanese (JIS-Allow 1 byte Kana) */
  CP_ISO_2022_JP_JIS         = 50222,	/**< ISO 2022 Japanese JIS X 0201-1989; Japanese (JIS-Allow 1 byte Kana - SO/SI) */
  CP_ISO_2022_KR             = 50225,	/**< ISO 2022 Korean */
  CP_X_CP50227               = 50227,	/**< ISO 2022 Simplified Chinese; Chinese Simplified (ISO 2022) */
  CP_EUC_JP                  = 51932,	/**< EUC Japanese */
  CP_EUC_CN                  = 51936,	/**< EUC Simplified Chinese; Chinese Simplified (EUC) */
  CP_EUC_KR                  = 51949,	/**< EUC Korean */
  CP_HZ_GB_2312              = 52936,	/**< HZ-GB2312 Simplified Chinese; Chinese Simplified (HZ) */
  CP_GB18030                 = 54936,	/**< Windows XP and later: GB18030 Simplified Chinese (4 byte); Chinese Simplified (GB18030) */
  CP_X_ISCII_DE              = 57002,	/**< ISCII Devanagari */
  CP_X_ISCII_BE              = 57003,	/**< ISCII Bengali */
  CP_X_ISCII_TA              = 57004,	/**< ISCII Tamil */
  CP_X_ISCII_TE              = 57005,	/**< ISCII Telugu */
  CP_X_ISCII_AS              = 57006,	/**< ISCII Assamese */
  CP_X_ISCII_OR              = 57007,	/**< ISCII Oriya */
  CP_X_ISCII_KA              = 57008,	/**< ISCII Kannada */
  CP_X_ISCII_MA              = 57009,	/**< ISCII Malayalam */
  CP_X_ISCII_GU              = 57010,	/**< ISCII Gujarati */
  CP_X_ISCII_PA              = 57011,	/**< ISCII Punjabi */
  CP_UTF_7                   = 65000,	/**< Unicode (UTF-7) */
  CP_UTF_8                   = 65001,	/**< Unicode (UTF-8) */
};
