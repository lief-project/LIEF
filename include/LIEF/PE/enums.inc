
enum _LIEF_EN(PE_TYPES) {
    _LIEF_EI(PE32)      = 0x10b, /** 32bits  */
    _LIEF_EI(PE32_PLUS) = 0x20b  /** 64 bits */
};

enum _LIEF_EN(MACHINE_TYPES) {
  _LIEF_EI(MT_Invalid) = 0xffff,
  _LIEF_EI(IMAGE_FILE_MACHINE_UNKNOWN)   = 0x0,
  _LIEF_EI(IMAGE_FILE_MACHINE_AM33)      = 0x13,   /**< Matsushita AM33               */
  _LIEF_EI(IMAGE_FILE_MACHINE_AMD64)     = 0x8664, /**< AMD x64                        */
  _LIEF_EI(IMAGE_FILE_MACHINE_ARM)       = 0x1C0,  /**< ARM little endian              */
  _LIEF_EI(IMAGE_FILE_MACHINE_ARMNT)     = 0x1C4,  /**< ARMv7 Thumb mode only          */
  _LIEF_EI(IMAGE_FILE_MACHINE_ARM64)     = 0xAA64, /**< ARMv8 in 64-bits mode          */
  _LIEF_EI(IMAGE_FILE_MACHINE_EBC)       = 0xEBC,  /**< EFI byte code                  */
  _LIEF_EI(IMAGE_FILE_MACHINE_I386)      = 0x14C,  /**< Intel 386 or later             */
  _LIEF_EI(IMAGE_FILE_MACHINE_IA64)      = 0x200,  /**< Intel Itanium processor family */
  _LIEF_EI(IMAGE_FILE_MACHINE_M32R)      = 0x9041, /**< Mitsubishi M32R little endian  */
  _LIEF_EI(IMAGE_FILE_MACHINE_MIPS16)    = 0x266,  /**< MIPS16                         */
  _LIEF_EI(IMAGE_FILE_MACHINE_MIPSFPU)   = 0x366,  /**< MIPS with FPU                  */
  _LIEF_EI(IMAGE_FILE_MACHINE_MIPSFPU16) = 0x466,  /**< MIPS16 with FPU                */
  _LIEF_EI(IMAGE_FILE_MACHINE_POWERPC)   = 0x1F0,  /**< Power PC little endian         */
  _LIEF_EI(IMAGE_FILE_MACHINE_POWERPCFP) = 0x1F1,  /**< Power PC with floating point   */
  _LIEF_EI(IMAGE_FILE_MACHINE_R4000)     = 0x166,  /**< MIPS with little endian        */
  _LIEF_EI(IMAGE_FILE_MACHINE_RISCV32)   = 0x5032, /**< RISC-V 32-bit address space    */
  _LIEF_EI(IMAGE_FILE_MACHINE_RISCV64)   = 0x5064, /**< RISC-V 64-bit address space    */
  _LIEF_EI(IMAGE_FILE_MACHINE_RISCV128)  = 0x166,  /**< RISC-V 128-bit address space   */
  _LIEF_EI(IMAGE_FILE_MACHINE_SH3)       = 0x1A2,  /**< Hitachi SH3                    */
  _LIEF_EI(IMAGE_FILE_MACHINE_SH3DSP)    = 0x1A3,  /**< Hitachi SH3 DSP                */
  _LIEF_EI(IMAGE_FILE_MACHINE_SH4)       = 0x1A6,  /**< Hitachi SH4                    */
  _LIEF_EI(IMAGE_FILE_MACHINE_SH5)       = 0x1A8,  /**< Hitachi SH5                    */
  _LIEF_EI(IMAGE_FILE_MACHINE_THUMB)     = 0x1C2,  /**< ARM or Thumb                   */
  _LIEF_EI(IMAGE_FILE_MACHINE_WCEMIPSV2) = 0x169   /**< MIPS little-endian WCE v2      */
};

enum _LIEF_EN_2(SYMBOL_SECTION_NUMBER, int) {
  _LIEF_EI(IMAGE_SYM_DEBUG)     = -2,
  _LIEF_EI(IMAGE_SYM_ABSOLUTE)  = -1,
  _LIEF_EI(IMAGE_SYM_UNDEFINED) = 0
};


enum _LIEF_EN(HEADER_CHARACTERISTICS) {
  _LIEF_EI(IMAGE_FILE_INVALID)                 = 0x0000,
  _LIEF_EI(IMAGE_FILE_RELOCS_STRIPPED)         = 0x0001, /**< The file does not contain base relocations and must be loaded at its preferred base. If this cannot be done, the loader will error.*/
  _LIEF_EI(IMAGE_FILE_EXECUTABLE_IMAGE)        = 0x0002, /**< The file is valid and can be run.*/
  _LIEF_EI(IMAGE_FILE_LINE_NUMS_STRIPPED)      = 0x0004, /**< COFF line numbers have been stripped. This is deprecated and should be 0*/
  _LIEF_EI(IMAGE_FILE_LOCAL_SYMS_STRIPPED)     = 0x0008, /**< COFF symbol table entries for local symbols have been removed. This is deprecated and should be 0.*/
  _LIEF_EI(IMAGE_FILE_AGGRESSIVE_WS_TRIM)      = 0x0010, /**< Aggressively trim working set. This is deprecated and must be 0.*/
  _LIEF_EI(IMAGE_FILE_LARGE_ADDRESS_AWARE)     = 0x0020, /**< Image can handle > 2GiB addresses. */
  _LIEF_EI(IMAGE_FILE_BYTES_REVERSED_LO)       = 0x0080, /**< Little endian: the LSB precedes the MSB in memory. This is deprecated and should be 0.*/
  _LIEF_EI(IMAGE_FILE_32BIT_MACHINE)           = 0x0100, /**< Machine is based on a 32bit word architecture. */
  _LIEF_EI(IMAGE_FILE_DEBUG_STRIPPED)          = 0x0200, /**< Debugging info has been removed. */
  _LIEF_EI(IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) = 0x0400, /**< If the image is on removable media, fully load it and copy it to swap. */
  _LIEF_EI(IMAGE_FILE_NET_RUN_FROM_SWAP)       = 0x0800, /**< If the image is on network media, fully load it and copy it to swap. */
  _LIEF_EI(IMAGE_FILE_SYSTEM)                  = 0x1000, /**< The image file is a system file, not a user program.*/
  _LIEF_EI(IMAGE_FILE_DLL)                     = 0x2000, /**< The image file is a DLL. */
  _LIEF_EI(IMAGE_FILE_UP_SYSTEM_ONLY)          = 0x4000, /**< This file should only be run on a uniprocessor machine. */
  _LIEF_EI(IMAGE_FILE_BYTES_REVERSED_HI)       = 0x8000  /**< Big endian: the MSB precedes the LSB in memory. This is deprecated */
};


/// Storage class tells where and what the symbol represents
enum _LIEF_EN_2(SYMBOL_STORAGE_CLASS, int) {
  _LIEF_EI(IMAGE_SYM_CLASS_INVALID) = 0xFF,

  _LIEF_EI(IMAGE_SYM_CLASS_END_OF_FUNCTION)  = -1,  ///< Physical end of function
  _LIEF_EI(IMAGE_SYM_CLASS_NULL)             = 0,   ///< No symbol
  _LIEF_EI(IMAGE_SYM_CLASS_AUTOMATIC)        = 1,   ///< Stack variable
  _LIEF_EI(IMAGE_SYM_CLASS_EXTERNAL)         = 2,   ///< External symbol
  _LIEF_EI(IMAGE_SYM_CLASS_STATIC)           = 3,   ///< Static
  _LIEF_EI(IMAGE_SYM_CLASS_REGISTER)         = 4,   ///< Register variable
  _LIEF_EI(IMAGE_SYM_CLASS_EXTERNAL_DEF)     = 5,   ///< External definition
  _LIEF_EI(IMAGE_SYM_CLASS_LABEL)            = 6,   ///< Label
  _LIEF_EI(IMAGE_SYM_CLASS_UNDEFINED_LABEL)  = 7,   ///< Undefined label
  _LIEF_EI(IMAGE_SYM_CLASS_MEMBER_OF_STRUCT) = 8,   ///< Member of structure
  _LIEF_EI(IMAGE_SYM_CLASS_ARGUMENT)         = 9,   ///< Function argument
  _LIEF_EI(IMAGE_SYM_CLASS_STRUCT_TAG)       = 10,  ///< Structure tag
  _LIEF_EI(IMAGE_SYM_CLASS_MEMBER_OF_UNION)  = 11,  ///< Member of union
  _LIEF_EI(IMAGE_SYM_CLASS_UNION_TAG)        = 12,  ///< Union tag
  _LIEF_EI(IMAGE_SYM_CLASS_TYPE_DEFINITION)  = 13,  ///< Type definition
  _LIEF_EI(IMAGE_SYM_CLASS_UNDEFINED_STATIC) = 14,  ///< Undefined static
  _LIEF_EI(IMAGE_SYM_CLASS_ENUM_TAG)         = 15,  ///< Enumeration tag
  _LIEF_EI(IMAGE_SYM_CLASS_MEMBER_OF_ENUM)   = 16,  ///< Member of enumeration
  _LIEF_EI(IMAGE_SYM_CLASS_REGISTER_PARAM)   = 17,  ///< Register parameter
  _LIEF_EI(IMAGE_SYM_CLASS_BIT_FIELD)        = 18,  ///< Bit field ".bb" or ".eb" - beginning or end of block
  _LIEF_EI(IMAGE_SYM_CLASS_BLOCK)            = 100, ///< ".bf" or ".ef" - beginning or end of function
  _LIEF_EI(IMAGE_SYM_CLASS_FUNCTION)         = 101,
  _LIEF_EI(IMAGE_SYM_CLASS_END_OF_STRUCT)    = 102, ///< End of structure
  _LIEF_EI(IMAGE_SYM_CLASS_FILE)             = 103, ///< File name line number, reformatted as symbol
  _LIEF_EI(IMAGE_SYM_CLASS_SECTION)          = 104,
  _LIEF_EI(IMAGE_SYM_CLASS_WEAK_EXTERNAL)    = 105, ///< Duplicate tag external symbol in dmert public lib
  _LIEF_EI(IMAGE_SYM_CLASS_CLR_TOKEN)        = 107
};


enum _LIEF_EN(SYMBOL_BASE_TYPES) {
  _LIEF_EI(IMAGE_SYM_TYPE_NULL)   = 0,  ///< No type information or unknown base type.
  _LIEF_EI(IMAGE_SYM_TYPE_VOID)   = 1,  ///< Used with void pointers and functions.
  _LIEF_EI(IMAGE_SYM_TYPE_CHAR)   = 2,  ///< A character (signed byte).
  _LIEF_EI(IMAGE_SYM_TYPE_SHORT)  = 3,  ///< A 2-byte signed integer.
  _LIEF_EI(IMAGE_SYM_TYPE_INT)    = 4,  ///< A natural integer type on the target.
  _LIEF_EI(IMAGE_SYM_TYPE_LONG)   = 5,  ///< A 4-byte signed integer.
  _LIEF_EI(IMAGE_SYM_TYPE_FLOAT)  = 6,  ///< A 4-byte floating-point number.
  _LIEF_EI(IMAGE_SYM_TYPE_DOUBLE) = 7,  ///< An 8-byte floating-point number.
  _LIEF_EI(IMAGE_SYM_TYPE_STRUCT) = 8,  ///< A structure.
  _LIEF_EI(IMAGE_SYM_TYPE_UNION)  = 9,  ///< An union.
  _LIEF_EI(IMAGE_SYM_TYPE_ENUM)   = 10, ///< An enumerated type.
  _LIEF_EI(IMAGE_SYM_TYPE_MOE)    = 11, ///< A member of enumeration (a specific value).
  _LIEF_EI(IMAGE_SYM_TYPE_BYTE)   = 12, ///< A byte; unsigned 1-byte integer.
  _LIEF_EI(IMAGE_SYM_TYPE_WORD)   = 13, ///< A word; unsigned 2-byte integer.
  _LIEF_EI(IMAGE_SYM_TYPE_UINT)   = 14, ///< An unsigned integer of natural size.
  _LIEF_EI(IMAGE_SYM_TYPE_DWORD)  = 15  ///< An unsigned 4-byte integer.
};

enum _LIEF_EN(SYMBOL_COMPLEX_TYPES) {
  _LIEF_EI(IMAGE_SYM_DTYPE_NULL)     = 0, ///< No complex type; simple scalar variable.
  _LIEF_EI(IMAGE_SYM_DTYPE_POINTER)  = 1, ///< A pointer to base type.
  _LIEF_EI(IMAGE_SYM_DTYPE_FUNCTION) = 2, ///< A function that returns a base type.
  _LIEF_EI(IMAGE_SYM_DTYPE_ARRAY)    = 3, ///< An array of base type.
  _LIEF_EI(SCT_COMPLEX_TYPE_SHIFT)   = 4  ///< Type is formed as (base + (derived << SCT_COMPLEX_TYPE_SHIFT))
};

enum _LIEF_EN(AuxSymbolType) {
  _LIEF_EI(IMAGE_AUX_SYMBOL_TYPE_TOKEN_DEF) = 1
};


enum _LIEF_EN(RELOCATIONS_BASE_TYPES) {
  _LIEF_EI(IMAGE_REL_BASED_ABSOLUTE)       = 0,
  _LIEF_EI(IMAGE_REL_BASED_HIGH)           = 1,
  _LIEF_EI(IMAGE_REL_BASED_LOW)            = 2,
  _LIEF_EI(IMAGE_REL_BASED_HIGHLOW)        = 3,
  _LIEF_EI(IMAGE_REL_BASED_HIGHADJ)        = 4,
  _LIEF_EI(IMAGE_REL_BASED_MIPS_JMPADDR)   = 5,
  _LIEF_EI(IMAGE_REL_BASED_SECTION)        = 6,
  _LIEF_EI(IMAGE_REL_BASED_REL)            = 7,
  _LIEF_EI(IMAGE_REL_BASED_MIPS_JMPADDR16) = 9,
  _LIEF_EI(IMAGE_REL_BASED_IA64_IMM64)     = 9,
  _LIEF_EI(IMAGE_REL_BASED_DIR64)          = 10,
  _LIEF_EI(IMAGE_REL_BASED_HIGH3ADJ)       = 11,
};

enum _LIEF_EN(RELOCATIONS_I386) {
  _LIEF_EI(IMAGE_REL_I386_ABSOLUTE) = 0x0000,
  _LIEF_EI(IMAGE_REL_I386_DIR16)    = 0x0001,
  _LIEF_EI(IMAGE_REL_I386_REL16)    = 0x0002,
  _LIEF_EI(IMAGE_REL_I386_DIR32)    = 0x0006,
  _LIEF_EI(IMAGE_REL_I386_DIR32NB)  = 0x0007,
  _LIEF_EI(IMAGE_REL_I386_SEG12)    = 0x0009,
  _LIEF_EI(IMAGE_REL_I386_SECTION)  = 0x000A,
  _LIEF_EI(IMAGE_REL_I386_SECREL)   = 0x000B,
  _LIEF_EI(IMAGE_REL_I386_TOKEN)    = 0x000C,
  _LIEF_EI(IMAGE_REL_I386_SECREL7)  = 0x000D,
  _LIEF_EI(IMAGE_REL_I386_REL32)    = 0x0014
};

enum _LIEF_EN(RELOCATIONS_AMD64) {
  _LIEF_EI(IMAGE_REL_AMD64_ABSOLUTE) = 0x0000,
  _LIEF_EI(IMAGE_REL_AMD64_ADDR64)   = 0x0001,
  _LIEF_EI(IMAGE_REL_AMD64_ADDR32)   = 0x0002,
  _LIEF_EI(IMAGE_REL_AMD64_ADDR32NB) = 0x0003,
  _LIEF_EI(IMAGE_REL_AMD64_REL32)    = 0x0004,
  _LIEF_EI(IMAGE_REL_AMD64_REL32_1)  = 0x0005,
  _LIEF_EI(IMAGE_REL_AMD64_REL32_2)  = 0x0006,
  _LIEF_EI(IMAGE_REL_AMD64_REL32_3)  = 0x0007,
  _LIEF_EI(IMAGE_REL_AMD64_REL32_4)  = 0x0008,
  _LIEF_EI(IMAGE_REL_AMD64_REL32_5)  = 0x0009,
  _LIEF_EI(IMAGE_REL_AMD64_SECTION)  = 0x000A,
  _LIEF_EI(IMAGE_REL_AMD64_SECREL)   = 0x000B,
  _LIEF_EI(IMAGE_REL_AMD64_SECREL7)  = 0x000C,
  _LIEF_EI(IMAGE_REL_AMD64_TOKEN)    = 0x000D,
  _LIEF_EI(IMAGE_REL_AMD64_SREL32)   = 0x000E,
  _LIEF_EI(IMAGE_REL_AMD64_PAIR)     = 0x000F,
  _LIEF_EI(IMAGE_REL_AMD64_SSPAN32)  = 0x0010
};

enum _LIEF_EN(RELOCATIONS_ARM) {
  _LIEF_EI(IMAGE_REL_ARM_ABSOLUTE)  = 0x0000,
  _LIEF_EI(IMAGE_REL_ARM_ADDR32)    = 0x0001,
  _LIEF_EI(IMAGE_REL_ARM_ADDR32NB)  = 0x0002,
  _LIEF_EI(IMAGE_REL_ARM_BRANCH24)  = 0x0003,
  _LIEF_EI(IMAGE_REL_ARM_BRANCH11)  = 0x0004,
  _LIEF_EI(IMAGE_REL_ARM_TOKEN)     = 0x0005,
  _LIEF_EI(IMAGE_REL_ARM_BLX24)     = 0x0008,
  _LIEF_EI(IMAGE_REL_ARM_BLX11)     = 0x0009,
  _LIEF_EI(IMAGE_REL_ARM_SECTION)   = 0x000E,
  _LIEF_EI(IMAGE_REL_ARM_SECREL)    = 0x000F,
  _LIEF_EI(IMAGE_REL_ARM_MOV32A)    = 0x0010,
  _LIEF_EI(IMAGE_REL_ARM_MOV32T)    = 0x0011,
  _LIEF_EI(IMAGE_REL_ARM_BRANCH20T) = 0x0012,
  _LIEF_EI(IMAGE_REL_ARM_BRANCH24T) = 0x0014,
  _LIEF_EI(IMAGE_REL_ARM_BLX23T)    = 0x0015
};


/// These are not documented in the spec, but are located in WinNT.h.
enum _LIEF_EN(WeakExternalCharacteristics) {
  _LIEF_EI(IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY) = 1,
  _LIEF_EI(IMAGE_WEAK_EXTERN_SEARCH_LIBRARY)   = 2,
  _LIEF_EI(IMAGE_WEAK_EXTERN_SEARCH_ALIAS)     = 3
};


enum _LIEF_EN(DATA_DIRECTORY) {
  _LIEF_EI(EXPORT_TABLE)            = 0,
  _LIEF_EI(IMPORT_TABLE)            = 1,
  _LIEF_EI(RESOURCE_TABLE)          = 2,
  _LIEF_EI(EXCEPTION_TABLE)         = 3,
  _LIEF_EI(CERTIFICATE_TABLE)       = 4,
  _LIEF_EI(BASE_RELOCATION_TABLE)   = 5,
  _LIEF_EI(DEBUG)                   = 6,
  _LIEF_EI(ARCHITECTURE)            = 7,
  _LIEF_EI(GLOBAL_PTR)              = 8,
  _LIEF_EI(TLS_TABLE)               = 9,
  _LIEF_EI(LOAD_CONFIG_TABLE)       = 10,
  _LIEF_EI(BOUND_IMPORT)            = 11,
  _LIEF_EI(IAT)                     = 12,
  _LIEF_EI(DELAY_IMPORT_DESCRIPTOR) = 13,
  _LIEF_EI(CLR_RUNTIME_HEADER)      = 14,

  _LIEF_EI(NUM_DATA_DIRECTORIES)    = 15
};


enum _LIEF_EN(SUBSYSTEM) {
  _LIEF_EI(IMAGE_SUBSYSTEM_UNKNOWN)                  = 0,  ///< An unknown subsystem.
  _LIEF_EI(IMAGE_SUBSYSTEM_NATIVE)                   = 1,  ///< Device drivers and native Windows processes
  _LIEF_EI(IMAGE_SUBSYSTEM_WINDOWS_GUI)              = 2,  ///< The Windows GUI subsystem.
  _LIEF_EI(IMAGE_SUBSYSTEM_WINDOWS_CUI)              = 3,  ///< The Windows character subsystem.
  _LIEF_EI(IMAGE_SUBSYSTEM_OS2_CUI)                  = 5,  ///< The OS/2 character subsytem.
  _LIEF_EI(IMAGE_SUBSYSTEM_POSIX_CUI)                = 7,  ///< The POSIX character subsystem.
  _LIEF_EI(IMAGE_SUBSYSTEM_NATIVE_WINDOWS)           = 8,  ///< Native Windows 9x driver.
  _LIEF_EI(IMAGE_SUBSYSTEM_WINDOWS_CE_GUI)           = 9,  ///< Windows CE.
  _LIEF_EI(IMAGE_SUBSYSTEM_EFI_APPLICATION)          = 10, ///< An EFI application.
  _LIEF_EI(IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER)  = 11, ///< An EFI driver with boot services.
  _LIEF_EI(IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER)       = 12, ///< An EFI driver with run-time services.
  _LIEF_EI(IMAGE_SUBSYSTEM_EFI_ROM)                  = 13, ///< An EFI ROM image.
  _LIEF_EI(IMAGE_SUBSYSTEM_XBOX)                     = 14, ///< XBOX.
  _LIEF_EI(IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION) = 16  ///< A BCD application.
};

enum _LIEF_EN(DLL_CHARACTERISTICS) {
  _LIEF_EI(IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA)       = 0x0020, ///< ASLR with 64 bit address space.
  _LIEF_EI(IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE)          = 0x0040, ///< DLL can be relocated at load time.
  _LIEF_EI(IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY)       = 0x0080, ///< Code integrity checks are enforced.
  _LIEF_EI(IMAGE_DLL_CHARACTERISTICS_NX_COMPAT)             = 0x0100, ///< Image is NX compatible.
  _LIEF_EI(IMAGE_DLL_CHARACTERISTICS_NO_ISOLATION)          = 0x0200, ///< Isolation aware, but do not isolate the image.
  _LIEF_EI(IMAGE_DLL_CHARACTERISTICS_NO_SEH)                = 0x0400, ///< Does not use structured exception handling (SEH). No SEH handler may be called in this image.
  _LIEF_EI(IMAGE_DLL_CHARACTERISTICS_NO_BIND)               = 0x0800, ///< Do not bind the image.
  _LIEF_EI(IMAGE_DLL_CHARACTERISTICS_APPCONTAINER)          = 0x1000, ///< Image should execute in an AppContainer.
  _LIEF_EI(IMAGE_DLL_CHARACTERISTICS_WDM_DRIVER)            = 0x2000, ///< A WDM driver.
  _LIEF_EI(IMAGE_DLL_CHARACTERISTICS_GUARD_CF)              = 0x4000, ///< Image supports Control Flow Guard.
  _LIEF_EI(IMAGE_DLL_CHARACTERISTICS_TERMINAL_SERVER_AWARE) = 0x8000  ///< Terminal Server aware.
};


enum _LIEF_EN(DEBUG_TYPES) {
  _LIEF_EI(IMAGE_DEBUG_TYPE_UNKNOWN)       = 0,
  _LIEF_EI(IMAGE_DEBUG_TYPE_COFF)          = 1, ///< COFF debug information
  _LIEF_EI(IMAGE_DEBUG_TYPE_CODEVIEW)      = 2, ///< CodeView debug information (pdb & cie)
  _LIEF_EI(IMAGE_DEBUG_TYPE_FPO)           = 3, ///< Frame pointer omission information
  _LIEF_EI(IMAGE_DEBUG_TYPE_MISC)          = 4, ///< CodeView Debug Information
  _LIEF_EI(IMAGE_DEBUG_TYPE_EXCEPTION)     = 5, ///< A copy of .pdata section.
  _LIEF_EI(IMAGE_DEBUG_TYPE_FIXUP)         = 6, ///< Reserved.
  _LIEF_EI(IMAGE_DEBUG_TYPE_OMAP_TO_SRC)   = 7, ///< The mapping from an RVA in image to an RVA in source image.
  _LIEF_EI(IMAGE_DEBUG_TYPE_OMAP_FROM_SRC) = 8, ///< The mapping from an RVA in source image to an RVA in image.
  _LIEF_EI(IMAGE_DEBUG_TYPE_BORLAND)       = 9, ///< Reserved for Borland.
  _LIEF_EI(IMAGE_DEBUG_TYPE_CLSID)         = 11,
  _LIEF_EI(IMAGE_DEBUG_TYPE_VC_FEATURE)    = 12,
  _LIEF_EI(IMAGE_DEBUG_TYPE_POGO)          = 13,
  _LIEF_EI(IMAGE_DEBUG_TYPE_ILTCG)         = 14,
  _LIEF_EI(IMAGE_DEBUG_TYPE_MPX)           = 15,
  _LIEF_EI(IMAGE_DEBUG_TYPE_REPRO)         = 16,
};


//! Code view signatures
//! @see: http://llvm.org/doxygen/CVDebugRecord_8h_source.html
enum _LIEF_EN(CODE_VIEW_SIGNATURES) {
  _LIEF_EI(CVS_UNKNOWN) = 0,
  _LIEF_EI(CVS_PDB_70) = 0x53445352, // RSDS
  _LIEF_EI(CVS_PDB_20) = 0x3031424e, // NB10
  _LIEF_EI(CVS_CV_50)  = 0x3131424e, // NB11
  _LIEF_EI(CVS_CV_41)  = 0x3930424e, // NB09
};

enum _LIEF_EN(ImportType) {
  _LIEF_EI(IMPORT_CODE)  = 0,
  _LIEF_EI(IMPORT_DATA)  = 1,
  _LIEF_EI(IMPORT_CONST) = 2
};


enum _LIEF_EN(ImportNameType) {
  /// Import is by ordinal. This indicates that the value in the Ordinal/Hint
  /// field of the import header is the import's ordinal. If this constant is
  /// not specified, then the Ordinal/Hint field should always be interpreted
  /// as the import's hint.
  _LIEF_EI(IMPORT_ORDINAL)         = 0,
  /// The import name is identical to the public symbol name
  _LIEF_EI(IMPORT_NAME)            = 1,
  /// The import name is the public symbol name, but skipping the leading ?,
  /// @, or optionally _.
  _LIEF_EI(IMPORT_NAME_NOPREFIX)   = 2,
  /// The import name is the public symbol name, but skipping the leading ?,
  /// @, or optionally _, and truncating at the first @.
  _LIEF_EI(IMPORT_NAME_UNDECORATE) = 3
};


enum _LIEF_EN(CodeViewIdentifiers) {
  _LIEF_EI(DEBUG_LINE_TABLES_HAVE_COLUMN_RECORDS) = 0x1,
  _LIEF_EI(DEBUG_SECTION_MAGIC) = 0x4,
  _LIEF_EI(DEBUG_SYMBOL_SUBSECTION) = 0xF1,
  _LIEF_EI(DEBUG_LINE_TABLE_SUBSECTION) = 0xF2,
  _LIEF_EI(DEBUG_STRING_TABLE_SUBSECTION) = 0xF3,
  _LIEF_EI(DEBUG_INDEX_SUBSECTION) = 0xF4,

  // Symbol subsections are split into records of different types.
  _LIEF_EI(DEBUG_SYMBOL_TYPE_PROC_START) = 0x1147,
  _LIEF_EI(DEBUG_SYMBOL_TYPE_PROC_END) = 0x114F
};


//
// Resources
//

//! @brief From https://msdn.microsoft.com/en-us/library/ms648009(v=vs.85).aspx
enum _LIEF_EN(RESOURCE_TYPES) {
  _LIEF_EI(CURSOR)       = 1,
  _LIEF_EI(BITMAP)       = 2,
  _LIEF_EI(ICON)         = 3,
  _LIEF_EI(MENU)         = 4,
  _LIEF_EI(DIALOG)       = 5,
  _LIEF_EI(STRING)       = 6,
  _LIEF_EI(FONTDIR)      = 7,
  _LIEF_EI(FONT)         = 8,
  _LIEF_EI(ACCELERATOR)  = 9,
  _LIEF_EI(RCDATA)       = 10,
  _LIEF_EI(MESSAGETABLE) = 11,
  _LIEF_EI(GROUP_CURSOR) = 12,
  _LIEF_EI(GROUP_ICON)   = 14,
  _LIEF_EI(VERSION)      = 16,
  _LIEF_EI(DLGINCLUDE)   = 17,
  _LIEF_EI(PLUGPLAY)     = 19,
  _LIEF_EI(VXD)          = 20,
  _LIEF_EI(ANICURSOR)    = 21,
  _LIEF_EI(ANIICON)      = 22,
  _LIEF_EI(HTML)         = 23,
  _LIEF_EI(MANIFEST)     = 24
};

enum _LIEF_EN(RESOURCE_LANGS) {
  _LIEF_EI(LANG_NEUTRAL)        = 0x00,
  _LIEF_EI(LANG_INVARIANT)      = 0x7f,
  _LIEF_EI(LANG_AFRIKAANS)      = 0x36,
  _LIEF_EI(LANG_ALBANIAN)       = 0x1c,
  _LIEF_EI(LANG_ARABIC)         = 0x01,
  _LIEF_EI(LANG_ARMENIAN)       = 0x2b,
  _LIEF_EI(LANG_ASSAMESE)       = 0x4d,
  _LIEF_EI(LANG_AZERI)          = 0x2c,
  _LIEF_EI(LANG_BASQUE)         = 0x2d,
  _LIEF_EI(LANG_BELARUSIAN)     = 0x23,
  _LIEF_EI(LANG_BENGALI)        = 0x45,
  _LIEF_EI(LANG_BULGARIAN)      = 0x02,
  _LIEF_EI(LANG_CATALAN)        = 0x03,
  _LIEF_EI(LANG_CHINESE)        = 0x04,
  _LIEF_EI(LANG_CROATIAN)       = 0x1a,
  _LIEF_EI(LANG_CZECH)          = 0x05,
  _LIEF_EI(LANG_DANISH)         = 0x06,
  _LIEF_EI(LANG_DIVEHI)         = 0x65,
  _LIEF_EI(LANG_DUTCH)          = 0x13,
  _LIEF_EI(LANG_ENGLISH)        = 0x09,
  _LIEF_EI(LANG_ESTONIAN)       = 0x25,
  _LIEF_EI(LANG_FAEROESE)       = 0x38,
  _LIEF_EI(LANG_FARSI)          = 0x29,
  _LIEF_EI(LANG_FINNISH)        = 0x0b,
  _LIEF_EI(LANG_FRENCH)         = 0x0c,
  _LIEF_EI(LANG_GALICIAN)       = 0x56,
  _LIEF_EI(LANG_GEORGIAN)       = 0x37,
  _LIEF_EI(LANG_GERMAN)         = 0x07,
  _LIEF_EI(LANG_GREEK)          = 0x08,
  _LIEF_EI(LANG_GUJARATI)       = 0x47,
  _LIEF_EI(LANG_HEBREW)         = 0x0d,
  _LIEF_EI(LANG_HINDI)          = 0x39,
  _LIEF_EI(LANG_HUNGARIAN)      = 0x0e,
  _LIEF_EI(LANG_ICELANDIC)      = 0x0f,
  _LIEF_EI(LANG_INDONESIAN)     = 0x21,
  _LIEF_EI(LANG_ITALIAN)        = 0x10,
  _LIEF_EI(LANG_JAPANESE)       = 0x11,
  _LIEF_EI(LANG_KANNADA)        = 0x4b,
  _LIEF_EI(LANG_KASHMIRI)       = 0x60,
  _LIEF_EI(LANG_KAZAK)          = 0x3f,
  _LIEF_EI(LANG_KONKANI)        = 0x57,
  _LIEF_EI(LANG_KOREAN)         = 0x12,
  _LIEF_EI(LANG_KYRGYZ)         = 0x40,
  _LIEF_EI(LANG_LATVIAN)        = 0x26,
  _LIEF_EI(LANG_LITHUANIAN)     = 0x27,
  _LIEF_EI(LANG_MACEDONIAN)     = 0x2f,
  _LIEF_EI(LANG_MALAY)          = 0x3e,
  _LIEF_EI(LANG_MALAYALAM)      = 0x4c,
  _LIEF_EI(LANG_MANIPURI)       = 0x58,
  _LIEF_EI(LANG_MARATHI)        = 0x4e,
  _LIEF_EI(LANG_MONGOLIAN)      = 0x50,
  _LIEF_EI(LANG_NEPALI)         = 0x61,
  _LIEF_EI(LANG_NORWEGIAN)      = 0x14,
  _LIEF_EI(LANG_ORIYA)          = 0x48,
  _LIEF_EI(LANG_POLISH)         = 0x15,
  _LIEF_EI(LANG_PORTUGUESE)     = 0x16,
  _LIEF_EI(LANG_PUNJABI)        = 0x46,
  _LIEF_EI(LANG_ROMANIAN)       = 0x18,
  _LIEF_EI(LANG_RUSSIAN)        = 0x19,
  _LIEF_EI(LANG_SANSKRIT)       = 0x4f,
  _LIEF_EI(LANG_SERBIAN)        = 0x1a,
  _LIEF_EI(LANG_SINDHI)         = 0x59,
  _LIEF_EI(LANG_SLOVAK)         = 0x1b,
  _LIEF_EI(LANG_SLOVENIAN)      = 0x24,
  _LIEF_EI(LANG_SPANISH)        = 0x0a,
  _LIEF_EI(LANG_SWAHILI)        = 0x41,
  _LIEF_EI(LANG_SWEDISH)        = 0x1d,
  _LIEF_EI(LANG_SYRIAC)         = 0x5a,
  _LIEF_EI(LANG_TAMIL)          = 0x49,
  _LIEF_EI(LANG_TATAR)          = 0x44,
  _LIEF_EI(LANG_TELUGU)         = 0x4a,
  _LIEF_EI(LANG_THAI)           = 0x1e,
  _LIEF_EI(LANG_TURKISH)        = 0x1f,
  _LIEF_EI(LANG_UKRAINIAN)      = 0x22,
  _LIEF_EI(LANG_URDU)           = 0x20,
  _LIEF_EI(LANG_UZBEK)          = 0x43,
  _LIEF_EI(LANG_VIETNAMESE)     = 0x2a,
  _LIEF_EI(LANG_GAELIC)         = 0x3c,
  _LIEF_EI(LANG_MALTESE)        = 0x3a,
  _LIEF_EI(LANG_MAORI)          = 0x28,
  _LIEF_EI(LANG_RHAETO_ROMANCE) = 0x17,
  _LIEF_EI(LANG_SAAMI)          = 0x3b,
  _LIEF_EI(LANG_SORBIAN)        = 0x2e,
  _LIEF_EI(LANG_SUTU)           = 0x30,
  _LIEF_EI(LANG_TSONGA)         = 0x31,
  _LIEF_EI(LANG_TSWANA)         = 0x32,
  _LIEF_EI(LANG_VENDA)          = 0x33,
  _LIEF_EI(LANG_XHOSA)          = 0x34,
  _LIEF_EI(LANG_ZULU)           = 0x35,
  _LIEF_EI(LANG_ESPERANTO)      = 0x8f,
  _LIEF_EI(LANG_WALON)          = 0x90,
  _LIEF_EI(LANG_CORNISH)        = 0x91,
  _LIEF_EI(LANG_WELSH)          = 0x92,
  _LIEF_EI(LANG_BRETON)         = 0x93
};


enum _LIEF_EN(RESOURCE_SUBLANGS) {
  _LIEF_EI(SUBLANG_NEUTRAL)                    =  0x00,
  _LIEF_EI(SUBLANG_DEFAULT)                    =  0x01,
  _LIEF_EI(SUBLANG_SYS_DEFAULT)                =  0x02,
  _LIEF_EI(SUBLANG_ARABIC_SAUDI_ARABIA)        =  0x01,
  _LIEF_EI(SUBLANG_ARABIC_IRAQ)                =  0x02,
  _LIEF_EI(SUBLANG_ARABIC_EGYPT)               =  0x03,
  _LIEF_EI(SUBLANG_ARABIC_LIBYA)               =  0x04,
  _LIEF_EI(SUBLANG_ARABIC_ALGERIA)             =  0x05,
  _LIEF_EI(SUBLANG_ARABIC_MOROCCO)             =  0x06,
  _LIEF_EI(SUBLANG_ARABIC_TUNISIA)             =  0x07,
  _LIEF_EI(SUBLANG_ARABIC_OMAN)                =  0x08,
  _LIEF_EI(SUBLANG_ARABIC_YEMEN)               =  0x09,
  _LIEF_EI(SUBLANG_ARABIC_SYRIA)               =  0x0a,
  _LIEF_EI(SUBLANG_ARABIC_JORDAN)              =  0x0b,
  _LIEF_EI(SUBLANG_ARABIC_LEBANON)             =  0x0c,
  _LIEF_EI(SUBLANG_ARABIC_KUWAIT)              =  0x0d,
  _LIEF_EI(SUBLANG_ARABIC_UAE)                 =  0x0e,
  _LIEF_EI(SUBLANG_ARABIC_BAHRAIN)             =  0x0f,
  _LIEF_EI(SUBLANG_ARABIC_QATAR)               =  0x10,
  _LIEF_EI(SUBLANG_AZERI_LATIN)                =  0x01,
  _LIEF_EI(SUBLANG_AZERI_CYRILLIC)             =  0x02,
  _LIEF_EI(SUBLANG_CHINESE_TRADITIONAL)        =  0x01,
  _LIEF_EI(SUBLANG_CHINESE_SIMPLIFIED)         =  0x02,
  _LIEF_EI(SUBLANG_CHINESE_HONGKONG)           =  0x03,
  _LIEF_EI(SUBLANG_CHINESE_SINGAPORE)          =  0x04,
  _LIEF_EI(SUBLANG_CHINESE_MACAU)              =  0x05,
  _LIEF_EI(SUBLANG_DUTCH)                      =  0x01,
  _LIEF_EI(SUBLANG_DUTCH_BELGIAN)              =  0x02,
  _LIEF_EI(SUBLANG_ENGLISH_US)                 =  0x01,
  _LIEF_EI(SUBLANG_ENGLISH_UK)                 =  0x02,
  _LIEF_EI(SUBLANG_ENGLISH_AUS)                =  0x03,
  _LIEF_EI(SUBLANG_ENGLISH_CAN)                =  0x04,
  _LIEF_EI(SUBLANG_ENGLISH_NZ)                 =  0x05,
  _LIEF_EI(SUBLANG_ENGLISH_EIRE)               =  0x06,
  _LIEF_EI(SUBLANG_ENGLISH_SOUTH_AFRICA)       =  0x07,
  _LIEF_EI(SUBLANG_ENGLISH_JAMAICA)            =  0x08,
  _LIEF_EI(SUBLANG_ENGLISH_CARIBBEAN)          =  0x09,
  _LIEF_EI(SUBLANG_ENGLISH_BELIZE)             =  0x0a,
  _LIEF_EI(SUBLANG_ENGLISH_TRINIDAD)           =  0x0b,
  _LIEF_EI(SUBLANG_ENGLISH_ZIMBABWE)           =  0x0c,
  _LIEF_EI(SUBLANG_ENGLISH_PHILIPPINES)        =  0x0d,
  _LIEF_EI(SUBLANG_FRENCH)                     =  0x01,
  _LIEF_EI(SUBLANG_FRENCH_BELGIAN)             =  0x02,
  _LIEF_EI(SUBLANG_FRENCH_CANADIAN)            =  0x03,
  _LIEF_EI(SUBLANG_FRENCH_SWISS)               =  0x04,
  _LIEF_EI(SUBLANG_FRENCH_LUXEMBOURG)          =  0x05,
  _LIEF_EI(SUBLANG_FRENCH_MONACO)              =  0x06,
  _LIEF_EI(SUBLANG_GERMAN)                     =  0x01,
  _LIEF_EI(SUBLANG_GERMAN_SWISS)               =  0x02,
  _LIEF_EI(SUBLANG_GERMAN_AUSTRIAN)            =  0x03,
  _LIEF_EI(SUBLANG_GERMAN_LUXEMBOURG)          =  0x04,
  _LIEF_EI(SUBLANG_GERMAN_LIECHTENSTEIN)       =  0x05,
  _LIEF_EI(SUBLANG_ITALIAN)                    =  0x01,
  _LIEF_EI(SUBLANG_ITALIAN_SWISS)              =  0x02,
  _LIEF_EI(SUBLANG_KASHMIRI_SASIA)             =  0x02,
  _LIEF_EI(SUBLANG_KASHMIRI_INDIA)             =  0x02,
  _LIEF_EI(SUBLANG_KOREAN)                     =  0x01,
  _LIEF_EI(SUBLANG_LITHUANIAN)                 =  0x01,
  _LIEF_EI(SUBLANG_MALAY_MALAYSIA)             =  0x01,
  _LIEF_EI(SUBLANG_MALAY_BRUNEI_DARUSSALAM)    =  0x02,
  _LIEF_EI(SUBLANG_NEPALI_INDIA)               =  0x02,
  _LIEF_EI(SUBLANG_NORWEGIAN_BOKMAL)           =  0x01,
  _LIEF_EI(SUBLANG_NORWEGIAN_NYNORSK)          =  0x02,
  _LIEF_EI(SUBLANG_PORTUGUESE)                 =  0x02,
  _LIEF_EI(SUBLANG_PORTUGUESE_BRAZILIAN)       =  0x01,
  _LIEF_EI(SUBLANG_SERBIAN_LATIN)              =  0x02,
  _LIEF_EI(SUBLANG_SERBIAN_CYRILLIC)           =  0x03,
  _LIEF_EI(SUBLANG_SPANISH)                    =  0x01,
  _LIEF_EI(SUBLANG_SPANISH_MEXICAN)            =  0x02,
  _LIEF_EI(SUBLANG_SPANISH_MODERN)             =  0x03,
  _LIEF_EI(SUBLANG_SPANISH_GUATEMALA)          =  0x04,
  _LIEF_EI(SUBLANG_SPANISH_COSTA_RICA)         =  0x05,
  _LIEF_EI(SUBLANG_SPANISH_PANAMA)             =  0x06,
  _LIEF_EI(SUBLANG_SPANISH_DOMINICAN_REPUBLIC) =  0x07,
  _LIEF_EI(SUBLANG_SPANISH_VENEZUELA)          =  0x08,
  _LIEF_EI(SUBLANG_SPANISH_COLOMBIA)           =  0x09,
  _LIEF_EI(SUBLANG_SPANISH_PERU)               =  0x0a,
  _LIEF_EI(SUBLANG_SPANISH_ARGENTINA)          =  0x0b,
  _LIEF_EI(SUBLANG_SPANISH_ECUADOR)            =  0x0c,
  _LIEF_EI(SUBLANG_SPANISH_CHILE)              =  0x0d,
  _LIEF_EI(SUBLANG_SPANISH_URUGUAY)            =  0x0e,
  _LIEF_EI(SUBLANG_SPANISH_PARAGUAY)           =  0x0f,
  _LIEF_EI(SUBLANG_SPANISH_BOLIVIA)            =  0x10,
  _LIEF_EI(SUBLANG_SPANISH_EL_SALVADOR)        =  0x11,
  _LIEF_EI(SUBLANG_SPANISH_HONDURAS)           =  0x12,
  _LIEF_EI(SUBLANG_SPANISH_NICARAGUA)          =  0x13,
  _LIEF_EI(SUBLANG_SPANISH_PUERTO_RICO)        =  0x14,
  _LIEF_EI(SUBLANG_SWEDISH)                    =  0x01,
  _LIEF_EI(SUBLANG_SWEDISH_FINLAND)            =  0x02,
  _LIEF_EI(SUBLANG_URDU_PAKISTAN)              =  0x01,
  _LIEF_EI(SUBLANG_URDU_INDIA)                 =  0x02,
  _LIEF_EI(SUBLANG_UZBEK_LATIN)                =  0x01,
  _LIEF_EI(SUBLANG_UZBEK_CYRILLIC)             =  0x02,
  _LIEF_EI(SUBLANG_DUTCH_SURINAM)              =  0x03,
  _LIEF_EI(SUBLANG_ROMANIAN)                   =  0x01,
  _LIEF_EI(SUBLANG_ROMANIAN_MOLDAVIA)          =  0x02,
  _LIEF_EI(SUBLANG_RUSSIAN)                    =  0x01,
  _LIEF_EI(SUBLANG_RUSSIAN_MOLDAVIA)           =  0x02,
  _LIEF_EI(SUBLANG_CROATIAN)                   =  0x01,
  _LIEF_EI(SUBLANG_LITHUANIAN_CLASSIC)         =  0x02,
  _LIEF_EI(SUBLANG_GAELIC)                     =  0x01,
  _LIEF_EI(SUBLANG_GAELIC_SCOTTISH)            =  0x02,
  _LIEF_EI(SUBLANG_GAELIC_MANX)                =  0x03,
};



enum _LIEF_EN(SECTION_CHARACTERISTICS) {
  _LIEF_EI(SC_Invalid) = 0xffffffff,

  _LIEF_EI(IMAGE_SCN_TYPE_NO_PAD)            = 0x00000008,
  _LIEF_EI(IMAGE_SCN_CNT_CODE)               = 0x00000020,
  _LIEF_EI(IMAGE_SCN_CNT_INITIALIZED_DATA)   = 0x00000040,
  _LIEF_EI(IMAGE_SCN_CNT_UNINITIALIZED_DATA) = 0x00000080,
  _LIEF_EI(IMAGE_SCN_LNK_OTHER)              = 0x00000100,
  _LIEF_EI(IMAGE_SCN_LNK_INFO)               = 0x00000200,
  _LIEF_EI(IMAGE_SCN_LNK_REMOVE)             = 0x00000800,
  _LIEF_EI(IMAGE_SCN_LNK_COMDAT)             = 0x00001000,
  _LIEF_EI(IMAGE_SCN_GPREL)                  = 0x00008000,
  _LIEF_EI(IMAGE_SCN_MEM_PURGEABLE)          = 0x00020000,
  _LIEF_EI(IMAGE_SCN_MEM_16BIT)              = 0x00020000,
  _LIEF_EI(IMAGE_SCN_MEM_LOCKED)             = 0x00040000,
  _LIEF_EI(IMAGE_SCN_MEM_PRELOAD)            = 0x00080000,
  _LIEF_EI(IMAGE_SCN_ALIGN_1BYTES)           = 0x00100000,
  _LIEF_EI(IMAGE_SCN_ALIGN_2BYTES)           = 0x00200000,
  _LIEF_EI(IMAGE_SCN_ALIGN_4BYTES)           = 0x00300000,
  _LIEF_EI(IMAGE_SCN_ALIGN_8BYTES)           = 0x00400000,
  _LIEF_EI(IMAGE_SCN_ALIGN_16BYTES)          = 0x00500000,
  _LIEF_EI(IMAGE_SCN_ALIGN_32BYTES)          = 0x00600000,
  _LIEF_EI(IMAGE_SCN_ALIGN_64BYTES)          = 0x00700000,
  _LIEF_EI(IMAGE_SCN_ALIGN_128BYTES)         = 0x00800000,
  _LIEF_EI(IMAGE_SCN_ALIGN_256BYTES)         = 0x00900000,
  _LIEF_EI(IMAGE_SCN_ALIGN_512BYTES)         = 0x00A00000,
  _LIEF_EI(IMAGE_SCN_ALIGN_1024BYTES)        = 0x00B00000,
  _LIEF_EI(IMAGE_SCN_ALIGN_2048BYTES)        = 0x00C00000,
  _LIEF_EI(IMAGE_SCN_ALIGN_4096BYTES)        = 0x00D00000,
  _LIEF_EI(IMAGE_SCN_ALIGN_8192BYTES)        = 0x00E00000,
  _LIEF_EI(IMAGE_SCN_LNK_NRELOC_OVFL)        = 0x01000000,
  _LIEF_EI(IMAGE_SCN_MEM_DISCARDABLE)        = 0x02000000,
  _LIEF_EI(IMAGE_SCN_MEM_NOT_CACHED)         = 0x04000000,
  _LIEF_EI(IMAGE_SCN_MEM_NOT_PAGED)          = 0x08000000,
  _LIEF_EI(IMAGE_SCN_MEM_SHARED)             = 0x10000000,
  _LIEF_EI(IMAGE_SCN_MEM_EXECUTE)            = 0x20000000,
  _LIEF_EI(IMAGE_SCN_MEM_READ)               = 0x40000000,
  _LIEF_EI(IMAGE_SCN_MEM_WRITE)              = 0x80000000
};

//! @brief From https://msdn.microsoft.com/en-us/library/ff700543.aspx
enum _LIEF_EN(EXTENDED_WINDOW_STYLES) {
  _LIEF_EI(WS_EX_DLGMODALFRAME)    = 0x00000001L,
  _LIEF_EI(WS_EX_NOPARENTNOTIFY)   = 0x00000004L,
  _LIEF_EI(WS_EX_TOPMOST)          = 0x00000008L,
  _LIEF_EI(WS_EX_ACCEPTFILES)      = 0x00000010L,
  _LIEF_EI(WS_EX_TRANSPARENT)      = 0x00000020L,
  _LIEF_EI(WS_EX_MDICHILD)         = 0x00000040L,
  _LIEF_EI(WS_EX_TOOLWINDOW)       = 0x00000080L,
  _LIEF_EI(WS_EX_WINDOWEDGE)       = 0x00000100L,
  _LIEF_EI(WS_EX_CLIENTEDGE)       = 0x00000200L,
  _LIEF_EI(WS_EX_CONTEXTHELP)      = 0x00000400L,

  _LIEF_EI(WS_EX_RIGHT)            = 0x00001000L,
  _LIEF_EI(WS_EX_LEFT)             = 0x00000000L,
  _LIEF_EI(WS_EX_RTLREADING)       = 0x00002000L,
  _LIEF_EI(WS_EX_LTRREADING)       = 0x00000000L,
  _LIEF_EI(WS_EX_LEFTSCROLLBAR)    = 0x00004000L,
  _LIEF_EI(WS_EX_RIGHTSCROLLBAR)   = 0x00000000L,

  _LIEF_EI(WS_EX_CONTROLPARENT)    = 0x00010000L,
  _LIEF_EI(WS_EX_STATICEDGE)       = 0x00020000L,
  _LIEF_EI(WS_EX_APPWINDOW)        = 0x00040000L,
};

//! @brief From: https://msdn.microsoft.com/en-us/library/ms632600.aspx
enum _LIEF_EN(WINDOW_STYLES) {
  _LIEF_EI(WS_OVERLAPPED)      = 0x00000000L,
  _LIEF_EI(WS_POPUP)           = 0x80000000L,
  _LIEF_EI(WS_CHILD)           = 0x40000000L,
  _LIEF_EI(WS_MINIMIZE)        = 0x20000000L,
  _LIEF_EI(WS_VISIBLE)         = 0x10000000L,
  _LIEF_EI(WS_DISABLED)        = 0x08000000L,
  _LIEF_EI(WS_CLIPSIBLINGS)    = 0x04000000L,
  _LIEF_EI(WS_CLIPCHILDREN)    = 0x02000000L,
  _LIEF_EI(WS_MAXIMIZE)        = 0x01000000L,
  _LIEF_EI(WS_CAPTION)         = 0x00C00000L,
  _LIEF_EI(WS_BORDER)          = 0x00800000L,
  _LIEF_EI(WS_DLGFRAME)        = 0x00400000L,
  _LIEF_EI(WS_VSCROLL)         = 0x00200000L,
  _LIEF_EI(WS_HSCROLL)         = 0x00100000L,
  _LIEF_EI(WS_SYSMENU)         = 0x00080000L,
  _LIEF_EI(WS_THICKFRAME)      = 0x00040000L,
  _LIEF_EI(WS_GROUP)           = 0x00020000L,
  _LIEF_EI(WS_TABSTOP)         = 0x00010000L,

  _LIEF_EI(WS_MINIMIZEBOX)     = 0x00020000L,
  _LIEF_EI(WS_MAXIMIZEBOX)     = 0x00010000L,
};


//! @brief From https://msdn.microsoft.com/en-us/library/ff729172.aspx
enum _LIEF_EN(DIALOG_BOX_STYLES) {
  _LIEF_EI(DS_ABSALIGN)      = 0x0001L,
  _LIEF_EI(DS_SYSMODAL)      = 0x0002L,
  _LIEF_EI(DS_LOCALEDIT)     = 0x0020L,
  _LIEF_EI(DS_SETFONT)       = 0x0040L,
  _LIEF_EI(DS_MODALFRAME)    = 0x0080L,
  _LIEF_EI(DS_NOIDLEMSG)     = 0x0100L,
  _LIEF_EI(DS_SETFOREGROUND) = 0x0200L,
  _LIEF_EI(DS_3DLOOK)        = 0x0004L,
  _LIEF_EI(DS_FIXEDSYS)      = 0x0008L,
  _LIEF_EI(DS_NOFAILCREATE)  = 0x0010L,
  _LIEF_EI(DS_CONTROL)       = 0x0400L,
  _LIEF_EI(DS_CENTER)        = 0x0800L,
  _LIEF_EI(DS_CENTERMOUSE)   = 0x1000L,
  _LIEF_EI(DS_CONTEXTHELP)   = 0x2000L,
  _LIEF_EI(DS_SHELLFONT)     = 0x0040L | 0x0008L, // DS_SETFONT | DS_FIXEDSYS
};

enum _LIEF_EN(FIXED_VERSION_OS) {
  _LIEF_EI(VOS_UNKNOWN)       = 0x00000000L,
  _LIEF_EI(VOS_DOS)           = 0x00010000L,
  _LIEF_EI(VOS_NT)            = 0x00040000L,
  _LIEF_EI(VOS__WINDOWS16)    = 0x00000001L,
  _LIEF_EI(VOS__WINDOWS32)    = 0x00000004L,
  _LIEF_EI(VOS_OS216)         = 0x00020000L,
  _LIEF_EI(VOS_OS232)         = 0x00030000L,
  _LIEF_EI(VOS__PM16)         = 0x00000002L,
  _LIEF_EI(VOS__PM32)         = 0x00000003L,
  _LIEF_EI(VOS_DOS_WINDOWS16) = 0x00010000L | 0x00000001L, // VOS_DOS   | VOS__WINDOWS16
  _LIEF_EI(VOS_DOS_WINDOWS32) = 0x00010000L | 0x00000004L, // VOS_DOS   | VOS__WINDOWS32
  _LIEF_EI(VOS_NT_WINDOWS32)  = 0x00040000L | 0x00000004L, // VOS_NT    | VOS__WINDOWS32
  _LIEF_EI(VOS_OS216_PM16)    = 0x00020000L | 0x00000002L, // VOS_OS216 | VOS__PM16
  _LIEF_EI(VOS_OS232_PM32)    = 0x00030000L | 0x00000003L, // VOS_OS232 | VOS__PM32
};


enum _LIEF_EN(FIXED_VERSION_FILE_FLAGS) {
  _LIEF_EI(VS_FF_DEBUG)        = 0x00000001L,
  _LIEF_EI(VS_FF_INFOINFERRED) = 0x00000010L,
  _LIEF_EI(VS_FF_PATCHED)      = 0x00000004L,
  _LIEF_EI(VS_FF_PRERELEASE)   = 0x00000002L,
  _LIEF_EI(VS_FF_PRIVATEBUILD) = 0x00000008L,
  _LIEF_EI(VS_FF_SPECIALBUILD) = 0x00000020L,
};


enum _LIEF_EN(FIXED_VERSION_FILE_TYPES) {
  _LIEF_EI(VFT_APP)        = 0x00000001L,
  _LIEF_EI(VFT_DLL)        = 0x00000002L,
  _LIEF_EI(VFT_DRV)        = 0x00000003L,
  _LIEF_EI(VFT_FONT)       = 0x00000004L,
  _LIEF_EI(VFT_STATIC_LIB) = 0x00000007L,
  _LIEF_EI(VFT_UNKNOWN)    = 0x00000000L,
  _LIEF_EI(VFT_VXD)        = 0x00000005L,
};


enum _LIEF_EN(FIXED_VERSION_FILE_SUB_TYPES) {
  _LIEF_EI(VFT2_DRV_COMM)              = 0x0000000AL,
  _LIEF_EI(VFT2_DRV_DISPLAY)           = 0x00000004L,
  _LIEF_EI(VFT2_DRV_INSTALLABLE)       = 0x00000008L,
  _LIEF_EI(VFT2_DRV_KEYBOARD)          = 0x00000002L,
  _LIEF_EI(VFT2_DRV_LANGUAGE)          = 0x00000003L,
  _LIEF_EI(VFT2_DRV_MOUSE)             = 0x00000005L,
  _LIEF_EI(VFT2_DRV_NETWORK)           = 0x00000006L,
  _LIEF_EI(VFT2_DRV_PRINTER)           = 0x00000001L,
  _LIEF_EI(VFT2_DRV_SOUND)             = 0x00000009L,
  _LIEF_EI(VFT2_DRV_SYSTEM)            = 0x00000007L,
  _LIEF_EI(VFT2_DRV_VERSIONED_PRINTER) = 0x0000000CL,
  _LIEF_EI(VFT2_FONT_RASTER)           = 0x00000001L,
  _LIEF_EI(VFT2_FONT_TRUETYPE)         = 0x00000003L,
  _LIEF_EI(VFT2_FONT_VECTOR)           = 0x00000002L,
  _LIEF_EI(VFT2_UNKNOWN)               = 0x00000000L,
};

//! @brief Code page from http://msdn.microsoft.com/en-us/library/ms776446(VS.85).aspx
enum _LIEF_EN(CODE_PAGES) {
  _LIEF_EI(CP_IBM037)                  = 37,		/**< IBM EBCDIC US-Canada */
  _LIEF_EI(CP_IBM437)                  = 437,		/**< OEM United States */
  _LIEF_EI(CP_IBM500)                  = 500,		/**< IBM EBCDIC International */
  _LIEF_EI(CP_ASMO_708)                = 708,		/**< Arabic (ASMO 708) */
  _LIEF_EI(CP_DOS_720)                 = 720,		/**< Arabic (Transparent ASMO); Arabic (DOS) */
  _LIEF_EI(CP_IBM737)                  = 737,		/**< OEM Greek (formerly 437G); Greek (DOS) */
  _LIEF_EI(CP_IBM775)                  = 775,		/**< OEM Baltic; Baltic (DOS) */
  _LIEF_EI(CP_IBM850)                  = 850,		/**< OEM Multilingual Latin 1; Western European (DOS) */
  _LIEF_EI(CP_IBM852)                  = 852,		/**< OEM Latin 2; Central European (DOS) */
  _LIEF_EI(CP_IBM855)                  = 855,		/**< OEM Cyrillic (primarily Russian) */
  _LIEF_EI(CP_IBM857)                  = 857,		/**< OEM Turkish; Turkish (DOS) */
  _LIEF_EI(CP_IBM00858)                = 858,		/**< OEM Multilingual Latin 1 + Euro symbol */
  _LIEF_EI(CP_IBM860)                  = 860,		/**< OEM Portuguese; Portuguese (DOS) */
  _LIEF_EI(CP_IBM861)                  = 861,		/**< OEM Icelandic; Icelandic (DOS) */
  _LIEF_EI(CP_DOS_862)                 = 862,		/**< OEM Hebrew; Hebrew (DOS) */
  _LIEF_EI(CP_IBM863)                  = 863,		/**< OEM French Canadian; French Canadian (DOS) */
  _LIEF_EI(CP_IBM864)                  = 864,		/**< OEM Arabic; Arabic (864) */
  _LIEF_EI(CP_IBM865)                  = 865,		/**< OEM Nordic; Nordic (DOS) */
  _LIEF_EI(CP_CP866)                   = 866,		/**< OEM Russian; Cyrillic (DOS) */
  _LIEF_EI(CP_IBM869)                  = 869,		/**< OEM Modern Greek; Greek, Modern (DOS) */
  _LIEF_EI(CP_IBM870)                  = 870,		/**< IBM EBCDIC Multilingual/ROECE (Latin 2); IBM EBCDIC Multilingual Latin 2 */
  _LIEF_EI(CP_WINDOWS_874)             = 874,		/**< ANSI/OEM Thai (same as 28605, ISO 8859-15); Thai (Windows) */
  _LIEF_EI(CP_CP875)                   = 875,		/**< IBM EBCDIC Greek Modern */
  _LIEF_EI(CP_SHIFT_JIS)               = 932,		/**< ANSI/OEM Japanese; Japanese (Shift-JIS) */
  _LIEF_EI(CP_GB2312)                  = 936,		/**< ANSI/OEM Simplified Chinese (PRC, Singapore); Chinese Simplified (GB2312) */
  _LIEF_EI(CP_KS_C_5601_1987)          = 949,		/**< ANSI/OEM Korean (Unified Hangul Code) */
  _LIEF_EI(CP_BIG5)                    = 950,		/**< ANSI/OEM Traditional Chinese (Taiwan; Hong Kong SAR, PRC); Chinese Traditional (Big5) */
  _LIEF_EI(CP_IBM1026)                 = 1026,	/**< IBM EBCDIC Turkish (Latin 5) */
  _LIEF_EI(CP_IBM01047)                = 1047,	/**< IBM EBCDIC Latin 1/Open System */
  _LIEF_EI(CP_IBM01140)                = 1140,	/**< IBM EBCDIC US-Canada (037 + Euro symbol); IBM EBCDIC (US-Canada-Euro) */
  _LIEF_EI(CP_IBM01141)                = 1141,	/**< IBM EBCDIC Germany (20273 + Euro symbol); IBM EBCDIC (Germany-Euro) */
  _LIEF_EI(CP_IBM01142)                = 1142,	/**< IBM EBCDIC Denmark-Norway (20277 + Euro symbol); IBM EBCDIC (Denmark-Norway-Euro) */
  _LIEF_EI(CP_IBM01143)                = 1143,	/**< IBM EBCDIC Finland-Sweden (20278 + Euro symbol); IBM EBCDIC (Finland-Sweden-Euro) */
  _LIEF_EI(CP_IBM01144)                = 1144,	/**< IBM EBCDIC Italy (20280 + Euro symbol); IBM EBCDIC (Italy-Euro) */
  _LIEF_EI(CP_IBM01145)                = 1145,	/**< IBM EBCDIC Latin America-Spain (20284 + Euro symbol); IBM EBCDIC (Spain-Euro) */
  _LIEF_EI(CP_IBM01146)                = 1146,	/**< IBM EBCDIC United Kingdom (20285 + Euro symbol); IBM EBCDIC (UK-Euro) */
  _LIEF_EI(CP_IBM01147)                = 1147,	/**< IBM EBCDIC France (20297 + Euro symbol); IBM EBCDIC (France-Euro) */
  _LIEF_EI(CP_IBM01148)                = 1148,	/**< IBM EBCDIC International (500 + Euro symbol); IBM EBCDIC (International-Euro) */
  _LIEF_EI(CP_IBM01149)                = 1149,	/**< IBM EBCDIC Icelandic (20871 + Euro symbol); IBM EBCDIC (Icelandic-Euro) */
  _LIEF_EI(CP_UTF_16)                  = 1200,	/**< Unicode UTF-16, little endian byte order (BMP of ISO 10646); available only to managed applications */
  _LIEF_EI(CP_UNICODEFFFE)             = 1201,	/**< Unicode UTF-16, big endian byte order; available only to managed applications */
  _LIEF_EI(CP_WINDOWS_1250)            = 1250,	/**< ANSI Central European; Central European (Windows) */
  _LIEF_EI(CP_WINDOWS_1251)            = 1251,	/**< ANSI Cyrillic; Cyrillic (Windows) */
  _LIEF_EI(CP_WINDOWS_1252)            = 1252,	/**< ANSI Latin 1; Western European (Windows) */
  _LIEF_EI(CP_WINDOWS_1253)            = 1253,	/**< ANSI Greek; Greek (Windows) */
  _LIEF_EI(CP_WINDOWS_1254)            = 1254,	/**< ANSI Turkish; Turkish (Windows) */
  _LIEF_EI(CP_WINDOWS_1255)            = 1255,	/**< ANSI Hebrew; Hebrew (Windows) */
  _LIEF_EI(CP_WINDOWS_1256)            = 1256,	/**< ANSI Arabic; Arabic (Windows) */
  _LIEF_EI(CP_WINDOWS_1257)            = 1257,	/**< ANSI Baltic; Baltic (Windows) */
  _LIEF_EI(CP_WINDOWS_1258)            = 1258,	/**< ANSI/OEM Vietnamese; Vietnamese (Windows) */
  _LIEF_EI(CP_JOHAB)                   = 1361,	/**< Korean (Johab) */
  _LIEF_EI(CP_MACINTOSH)               = 10000,	/**< MAC Roman; Western European (Mac) */
  _LIEF_EI(CP_X_MAC_JAPANESE)          = 10001,	/**< Japanese (Mac) */
  _LIEF_EI(CP_X_MAC_CHINESETRAD)       = 10002,	/**< MAC Traditional Chinese (Big5); Chinese Traditional (Mac) */
  _LIEF_EI(CP_X_MAC_KOREAN)            = 10003,	/**< Korean (Mac) */
  _LIEF_EI(CP_X_MAC_ARABIC)            = 10004,	/**< Arabic (Mac) */
  _LIEF_EI(CP_X_MAC_HEBREW)            = 10005,	/**< Hebrew (Mac) */
  _LIEF_EI(CP_X_MAC_GREEK)             = 10006,	/**< Greek (Mac) */
  _LIEF_EI(CP_X_MAC_CYRILLIC)          = 10007,	/**< Cyrillic (Mac) */
  _LIEF_EI(CP_X_MAC_CHINESESIMP)       = 10008,	/**< MAC Simplified Chinese (GB 2312); Chinese Simplified (Mac) */
  _LIEF_EI(CP_X_MAC_ROMANIAN)          = 10010,	/**< Romanian (Mac) */
  _LIEF_EI(CP_X_MAC_UKRAINIAN)         = 10017,	/**< Ukrainian (Mac) */
  _LIEF_EI(CP_X_MAC_THAI)              = 10021,	/**< Thai (Mac) */
  _LIEF_EI(CP_X_MAC_CE)                = 10029,	/**< MAC Latin 2; Central European (Mac) */
  _LIEF_EI(CP_X_MAC_ICELANDIC)         = 10079,	/**< Icelandic (Mac) */
  _LIEF_EI(CP_X_MAC_TURKISH)           = 10081,	/**< Turkish (Mac) */
  _LIEF_EI(CP_X_MAC_CROATIAN)          = 10082,	/**< Croatian (Mac) */
  _LIEF_EI(CP_UTF_32)                  = 12000,	/**< Unicode UTF-32, little endian byte order; available only to managed applications */
  _LIEF_EI(CP_UTF_32BE)                = 12001,	/**< Unicode UTF-32, big endian byte order; available only to managed applications */
  _LIEF_EI(CP_X_CHINESE_CNS)           = 20000,	/**< CNS Taiwan; Chinese Traditional (CNS) */
  _LIEF_EI(CP_X_CP20001)               = 20001,	/**< TCA Taiwan */
  _LIEF_EI(CP_X_CHINESE_ETEN)          = 20002,	/**< Eten Taiwan; Chinese Traditional (Eten) */
  _LIEF_EI(CP_X_CP20003)               = 20003,	/**< IBM5550 Taiwan */
  _LIEF_EI(CP_X_CP20004)               = 20004,	/**< TeleText Taiwan */
  _LIEF_EI(CP_X_CP20005)               = 20005,	/**< Wang Taiwan */
  _LIEF_EI(CP_X_IA5)                   = 20105,	/**< IA5 (IRV International Alphabet No. 5, 7-bit); Western European (IA5) */
  _LIEF_EI(CP_X_IA5_GERMAN)            = 20106,	/**< IA5 German (7-bit) */
  _LIEF_EI(CP_X_IA5_SWEDISH)           = 20107,	/**< IA5 Swedish (7-bit) */
  _LIEF_EI(CP_X_IA5_NORWEGIAN)         = 20108,	/**< IA5 Norwegian (7-bit) */
  _LIEF_EI(CP_US_ASCII)                = 20127,	/**< US-ASCII (7-bit) */
  _LIEF_EI(CP_X_CP20261)               = 20261,	/**< T.61 */
  _LIEF_EI(CP_X_CP20269)               = 20269,	/**< ISO 6937 Non-Spacing Accent */
  _LIEF_EI(CP_IBM273)                  = 20273,	/**< IBM EBCDIC Germany */
  _LIEF_EI(CP_IBM277)                  = 20277,	/**< IBM EBCDIC Denmark-Norway */
  _LIEF_EI(CP_IBM278)                  = 20278,	/**< IBM EBCDIC Finland-Sweden */
  _LIEF_EI(CP_IBM280)                  = 20280,	/**< IBM EBCDIC Italy */
  _LIEF_EI(CP_IBM284)                  = 20284,	/**< IBM EBCDIC Latin America-Spain */
  _LIEF_EI(CP_IBM285)                  = 20285,	/**< IBM EBCDIC United Kingdom */
  _LIEF_EI(CP_IBM290)                  = 20290,	/**< IBM EBCDIC Japanese Katakana Extended */
  _LIEF_EI(CP_IBM297)                  = 20297,	/**< IBM EBCDIC France */
  _LIEF_EI(CP_IBM420)                  = 20420,	/**< IBM EBCDIC Arabic */
  _LIEF_EI(CP_IBM423)                  = 20423,	/**< IBM EBCDIC Greek */
  _LIEF_EI(CP_IBM424)                  = 20424,	/**< IBM EBCDIC Hebrew */
  _LIEF_EI(CP_X_EBCDIC_KOREANEXTENDED) = 20833,	/**< IBM EBCDIC Korean Extended */
  _LIEF_EI(CP_IBM_THAI)                = 20838,	/**< IBM EBCDIC Thai */
  _LIEF_EI(CP_KOI8_R)                  = 20866,	/**< Russian (KOI8-R); Cyrillic (KOI8-R) */
  _LIEF_EI(CP_IBM871)                  = 20871,	/**< IBM EBCDIC Icelandic */
  _LIEF_EI(CP_IBM880)                  = 20880,	/**< IBM EBCDIC Cyrillic Russian */
  _LIEF_EI(CP_IBM905)                  = 20905,	/**< IBM EBCDIC Turkish */
  _LIEF_EI(CP_IBM00924)                = 20924,	/**< IBM EBCDIC Latin 1/Open System (1047 + Euro symbol) */
  _LIEF_EI(CP_EUC_JP_JIS)              = 20932,	/**< Japanese (JIS 0208-1990 and 0121-1990) */
  _LIEF_EI(CP_X_CP20936)               = 20936,	/**< Simplified Chinese (GB2312); Chinese Simplified (GB2312-80) */
  _LIEF_EI(CP_X_CP20949)               = 20949,	/**< Korean Wansung */
  _LIEF_EI(CP_CP1025)                  = 21025,	/**< IBM EBCDIC Cyrillic Serbian-Bulgarian */
  _LIEF_EI(CP_KOI8_U)                  = 21866,	/**< Ukrainian (KOI8-U); Cyrillic (KOI8-U) */
  _LIEF_EI(CP_ISO_8859_1)              = 28591,	/**< ISO 8859-1 Latin 1; Western European (ISO) */
  _LIEF_EI(CP_ISO_8859_2)              = 28592,	/**< ISO 8859-2 Central European; Central European (ISO) */
  _LIEF_EI(CP_ISO_8859_3)              = 28593,	/**< ISO 8859-3 Latin 3 */
  _LIEF_EI(CP_ISO_8859_4)              = 28594,	/**< ISO 8859-4 Baltic */
  _LIEF_EI(CP_ISO_8859_5)              = 28595,	/**< ISO 8859-5 Cyrillic */
  _LIEF_EI(CP_ISO_8859_6)              = 28596,	/**< ISO 8859-6 Arabic */
  _LIEF_EI(CP_ISO_8859_7)              = 28597,	/**< ISO 8859-7 Greek */
  _LIEF_EI(CP_ISO_8859_8)              = 28598,	/**< ISO 8859-8 Hebrew; Hebrew (ISO-Visual) */
  _LIEF_EI(CP_ISO_8859_9)              = 28599,	/**< ISO 8859-9 Turkish */
  _LIEF_EI(CP_ISO_8859_13)             = 28603,	/**< ISO 8859-13 Estonian */
  _LIEF_EI(CP_ISO_8859_15)             = 28605,	/**< ISO 8859-15 Latin 9 */
  _LIEF_EI(CP_X_EUROPA)                = 29001,	/**< Europa 3 */
  _LIEF_EI(CP_ISO_8859_8_I)            = 38598,	/**< ISO 8859-8 Hebrew; Hebrew (ISO-Logical) */
  _LIEF_EI(CP_ISO_2022_JP)             = 50220,	/**< ISO 2022 Japanese with no halfwidth Katakana; Japanese (JIS) */
  _LIEF_EI(CP_CSISO2022JP)             = 50221,	/**< ISO 2022 Japanese with halfwidth Katakana; Japanese (JIS-Allow 1 byte Kana) */
  _LIEF_EI(CP_ISO_2022_JP_JIS)         = 50222,	/**< ISO 2022 Japanese JIS X 0201-1989; Japanese (JIS-Allow 1 byte Kana - SO/SI) */
  _LIEF_EI(CP_ISO_2022_KR)             = 50225,	/**< ISO 2022 Korean */
  _LIEF_EI(CP_X_CP50227)               = 50227,	/**< ISO 2022 Simplified Chinese; Chinese Simplified (ISO 2022) */
  _LIEF_EI(CP_EUC_JP)                  = 51932,	/**< EUC Japanese */
  _LIEF_EI(CP_EUC_CN)                  = 51936,	/**< EUC Simplified Chinese; Chinese Simplified (EUC) */
  _LIEF_EI(CP_EUC_KR)                  = 51949,	/**< EUC Korean */
  _LIEF_EI(CP_HZ_GB_2312)              = 52936,	/**< HZ-GB2312 Simplified Chinese; Chinese Simplified (HZ) */
  _LIEF_EI(CP_GB18030)                 = 54936,	/**< Windows XP and later: GB18030 Simplified Chinese (4 byte); Chinese Simplified (GB18030) */
  _LIEF_EI(CP_X_ISCII_DE)              = 57002,	/**< ISCII Devanagari */
  _LIEF_EI(CP_X_ISCII_BE)              = 57003,	/**< ISCII Bengali */
  _LIEF_EI(CP_X_ISCII_TA)              = 57004,	/**< ISCII Tamil */
  _LIEF_EI(CP_X_ISCII_TE)              = 57005,	/**< ISCII Telugu */
  _LIEF_EI(CP_X_ISCII_AS)              = 57006,	/**< ISCII Assamese */
  _LIEF_EI(CP_X_ISCII_OR)              = 57007,	/**< ISCII Oriya */
  _LIEF_EI(CP_X_ISCII_KA)              = 57008,	/**< ISCII Kannada */
  _LIEF_EI(CP_X_ISCII_MA)              = 57009,	/**< ISCII Malayalam */
  _LIEF_EI(CP_X_ISCII_GU)              = 57010,	/**< ISCII Gujarati */
  _LIEF_EI(CP_X_ISCII_PA)              = 57011,	/**< ISCII Punjabi */
  _LIEF_EI(CP_UTF_7)                   = 65000,	/**< Unicode (UTF-7) */
  _LIEF_EI(CP_UTF_8)                   = 65001,	/**< Unicode (UTF-8) */
};

enum _LIEF_EN(WIN_VERSION) {
  _LIEF_EI(WIN_UNKNOWN)   = 0,
  _LIEF_EI(WIN_SEH)       = 1,
  _LIEF_EI(WIN8_1)        = 2,
  _LIEF_EI(WIN10_0_9879)  = 3,
  _LIEF_EI(WIN10_0_14286) = 4,
  _LIEF_EI(WIN10_0_14383) = 5,
  _LIEF_EI(WIN10_0_14901) = 6,
  _LIEF_EI(WIN10_0_15002) = 7,
  _LIEF_EI(WIN10_0_16237) = 8,
};

enum _LIEF_EN(GUARD_CF_FLAGS) {
  _LIEF_EI(GCF_NONE)                            = 0x00000000,
  _LIEF_EI(GCF_INSTRUMENTED)                    = 0x00000100, /**< Module performs control flow integrity checks using system-supplied support */
  _LIEF_EI(GCF_W_INSTRUMENTED)                  = 0x00000200, /**< Module performs control flow and write integrity checks */
  _LIEF_EI(GCF_FUNCTION_TABLE_PRESENT)          = 0x00000400, /**< Module contains valid control flow target metadata */
  _LIEF_EI(GCF_EXPORT_SUPPRESSION_INFO_PRESENT) = 0x00004000, /**< Module contains suppressed export information. This also infers that the address taken taken IAT table is also present in the load config. */
  _LIEF_EI(GCF_ENABLE_EXPORT_SUPPRESSION)       = 0x00008000, /**< Module enables suppression of exports */
  _LIEF_EI(GCF_LONGJUMP_TABLE_PRESENT)          = 0x00010000, /**< Module contains longjmp target information */
};

enum _LIEF_EN(GUARD_RF_FLAGS) {
  _LIEF_EI(GRF_INSTRUMENTED) = 0x00020000, /**< Module contains return flow instrumentation and metadata */
  _LIEF_EI(GRF_ENABLE)       = 0x00040000, /**< Module requests that the OS enable return flow protection */
  _LIEF_EI(GRF_STRICT)       = 0x00080000, /**< Module requests that the OS enable return flow protection in strict mode */
};





