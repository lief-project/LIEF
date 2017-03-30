//! The maximum number of sections that a COFF object can have (inclusive).
static const int32_t MaxNumberOfSections16 = 65279;

//! The PE signature bytes that follows the DOS stub header.
static const char PE_Magic[] = { 'P', 'E', '\0', '\0' };

static const char BigObjMagic[] = {
  '\xc7', '\xa1', '\xba', '\xd1', '\xee', '\xba', '\xa9', '\x4b',
  '\xaf', '\x20', '\xfa', '\xf6', '\x6a', '\xa4', '\xdc', '\xb8',
};

static const uint8_t DEFAULT_NUMBER_DATA_DIRECTORIES = 15;

#pragma pack(push,1)
struct pe_header {
  char     signature[sizeof(PE_Magic)];
  uint16_t Machine;
  uint16_t NumberOfSections;
  uint32_t TimeDateStamp;
  uint32_t PointerToSymbolTable;
  uint32_t NumberOfSymbols;
  uint16_t SizeOfOptionalHeader;
  uint16_t Characteristics;
};


struct pe_relocation {
  uint32_t VirtualAddress;
  uint32_t SymbolTableIndex;
  uint16_t Type;
};

struct pe_base_relocation_block {
  uint32_t PageRVA;
  uint32_t BlockSize;
};


struct pe_symbol {
  union {
    char ShortName[8];
    struct
		{
	    uint32_t Zeroes;
			uint32_t Offset;
    } Name;
  } Name;
  uint32_t Value;
  int16_t  SectionNumber;
  uint16_t Type;
  uint8_t  StorageClass;
  uint8_t  NumberOfAuxSymbols;
};


struct pe_section {
  char     Name[8];
  uint32_t VirtualSize;
  uint32_t VirtualAddress;
  uint32_t SizeOfRawData;
  uint32_t PointerToRawData;
  uint32_t PointerToRelocations;
  uint32_t PointerToLineNumbers;
  uint16_t NumberOfRelocations;
  uint16_t NumberOfLineNumbers;
  uint32_t Characteristics;
};

struct AuxiliaryFunctionDefinition {
  uint32_t TagIndex;
  uint32_t TotalSize;
  uint32_t PointerToLinenumber;
  uint32_t PointerToNextFunction;
  char     unused[2];
};

struct AuxiliarybfAndefSymbol {
  uint8_t  unused1[4];
  uint16_t Linenumber;
  uint8_t  unused2[6];
  uint32_t PointerToNextFunction;
  uint8_t  unused3[2];
};

struct AuxiliaryWeakExternal {
  uint32_t TagIndex;
  uint32_t Characteristics;
  uint8_t  unused[10];
};


struct AuxiliarySectionDefinition {
  uint32_t Length;
  uint16_t NumberOfRelocations;
  uint16_t NumberOfLinenumbers;
  uint32_t CheckSum;
  uint32_t Number;
  uint8_t  Selection;
  char     unused;
};

struct AuxiliaryCLRToken {
  uint8_t  AuxType;
  uint8_t  unused1;
  uint32_t SymbolTableIndex;
  char     unused2[12];
};

union Auxiliary {
  AuxiliaryFunctionDefinition FunctionDefinition;
  AuxiliarybfAndefSymbol      bfAndefSymbol;
  AuxiliaryWeakExternal       WeakExternal;
  AuxiliarySectionDefinition  SectionDefinition;
};


/// @brief The Import Directory Table.
///
/// There is a single array of these and one entry per imported DLL.
struct pe_import {
  uint32_t ImportLookupTableRVA;
  uint32_t TimeDateStamp;
  uint32_t ForwarderChain;
  uint32_t NameRVA;
  uint32_t ImportAddressTableRVA;
};


struct ImportLookupTableEntry32 {
  uint32_t data;
};

struct ImportLookupTableEntry64 {
  uint64_t data;
};


struct pe32_tls {
  uint32_t RawDataStartVA;
  uint32_t RawDataEndVA;
  uint32_t AddressOfIndex;
  uint32_t AddressOfCallback;
  uint32_t SizeOfZeroFill;
  uint32_t Characteristics;
};


struct pe64_tls {
  uint64_t RawDataStartVA;
  uint64_t RawDataEndVA;
  uint64_t AddressOfIndex;
  uint64_t AddressOfCallback;
  uint32_t SizeOfZeroFill;
  uint32_t Characteristics;
};


/// @brief The DOS compatible header at the front of all PEs.
struct pe_dos_header {
  uint16_t Magic;
  uint16_t UsedBytesInTheLastPage;
  uint16_t FileSizeInPages;
  uint16_t NumberOfRelocationItems;
  uint16_t HeaderSizeInParagraphs;
  uint16_t MinimumExtraParagraphs;
  uint16_t MaximumExtraParagraphs;
  uint16_t InitialRelativeSS;
  uint16_t InitialSP;
  uint16_t Checksum;
  uint16_t InitialIP;
  uint16_t InitialRelativeCS;
  uint16_t AddressOfRelocationTable;
  uint16_t OverlayNumber;
  uint16_t Reserved[4];
  uint16_t OEMid;
  uint16_t OEMinfo;
  uint16_t Reserved2[10];
  uint32_t AddressOfNewExeHeader;
};

struct pe64_optional_header {
  uint16_t Magic;
  uint8_t  MajorLinkerVersion;
  uint8_t  MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint; // RVA
  uint32_t BaseOfCode; // RVA
  //uint32_t BaseOfData; // RVA
  uint64_t ImageBase;
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DLLCharacteristics;
  uint64_t SizeOfStackReserve;
  uint64_t SizeOfStackCommit;
  uint64_t SizeOfHeapReserve;
  uint64_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSize;
};


struct pe32_optional_header {
  uint16_t Magic;
  uint8_t  MajorLinkerVersion;
  uint8_t  MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint; // RVA
  uint32_t BaseOfCode; // RVA
  uint32_t BaseOfData; // RVA
  uint32_t ImageBase;
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DLLCharacteristics;
  uint32_t SizeOfStackReserve;
  uint32_t SizeOfStackCommit;
  uint32_t SizeOfHeapReserve;
  uint32_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSize;
};


struct pe_data_directory {
  uint32_t RelativeVirtualAddress;
  uint32_t Size;
};


struct pe_debug {
  uint32_t Characteristics;
  uint32_t TimeDateStamp;
  uint16_t MajorVersion;
  uint16_t MinorVersion;
  uint32_t Type;
  uint32_t SizeOfData;
  uint32_t AddressOfRawData;
  uint32_t PointerToRawData;
};


struct pe_resource_directory_table {
  uint32_t Characteristics;
  uint32_t TimeDateStamp;
  uint16_t MajorVersion;
  uint16_t MinorVersion;
  uint16_t NumberOfNameEntries;
  uint16_t NumberOfIDEntries;
};

struct pe_resource_directory_entries {
  union {
    uint32_t NameRVA;
    uint32_t IntegerID;
  } NameID;
  uint32_t RVA;
};

struct pe_resource_data_entry {
  uint32_t DataRVA;
  uint32_t Size;
  uint32_t Codepage;
  uint32_t Reserved;
};

struct pe_resource_string {
  int16_t Length;
  uint16_t Name[1];
};


//
// Export structures
//
struct pe_export_directory_table {
  uint32_t ExportFlags;           ///< Reserverd must be 0
  uint32_t Timestamp;             ///< The time and date that the export data was created
  uint16_t MajorVersion;          ///< The Major version number
  uint16_t MinorVersion;          ///< The Minor version number
  uint32_t NameRVA;               ///< The address of the ASCII DLL's name (RVA)
  uint32_t OrdinalBase;           ///< The starting ordinal number for exports. (Usually 1)
  uint32_t AddressTableEntries;   ///< Number of entries in the export address table
  uint32_t NumberOfNamePointers;  ///< Number of entries in the name pointer table
  uint32_t ExportAddressTableRVA; ///< Address of the export address table (RVA)
  uint32_t NamePointerRVA;        ///< Address of the name pointer table (RVA)
  uint32_t OrdinalTableRVA;       ///< Address of the ordinal table (RVA)
};
#pragma pack(pop)
