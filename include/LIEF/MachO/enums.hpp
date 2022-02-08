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
#ifndef LIEF_MACHO_ENUMS_H_
#define LIEF_MACHO_ENUMS_H_

#include "LIEF/MachO/undef.h"
#include "LIEF/enums.hpp"
#include <cstdint>
#include <cstddef>

namespace LIEF {
namespace MachO {

enum class MACHO_TYPES: uint32_t {
  MH_MAGIC    = 0xFEEDFACEu, ///< 32-bit big-endian magic
  MH_CIGAM    = 0xCEFAEDFEu, ///< 32-bit little-endian magic
  MH_MAGIC_64 = 0xFEEDFACFu, ///< 64-bit big-endian magic
  MH_CIGAM_64 = 0xCFFAEDFEu, ///< 64-bit little-endian magic
  FAT_MAGIC   = 0xCAFEBABEu, ///< big-endian fat magic
  FAT_CIGAM   = 0xBEBAFECAu  ///< little-endian fat magic
};

enum class FILE_TYPES: size_t  {
  MH_OBJECT      = 0x1u,
  MH_EXECUTE     = 0x2u,
  MH_FVMLIB      = 0x3u,
  MH_CORE        = 0x4u,
  MH_PRELOAD     = 0x5u,
  MH_DYLIB       = 0x6u,
  MH_DYLINKER    = 0x7u,
  MH_BUNDLE      = 0x8u,
  MH_DYLIB_STUB  = 0x9u,
  MH_DSYM        = 0xAu,
  MH_KEXT_BUNDLE = 0xBu
};


enum class HEADER_FLAGS: size_t  {
  MH_NOUNDEFS                = 0x00000001u,
  MH_INCRLINK                = 0x00000002u,
  MH_DYLDLINK                = 0x00000004u,
  MH_BINDATLOAD              = 0x00000008u,
  MH_PREBOUND                = 0x00000010u,
  MH_SPLIT_SEGS              = 0x00000020u,
  MH_LAZY_INIT               = 0x00000040u,
  MH_TWOLEVEL                = 0x00000080u,
  MH_FORCE_FLAT              = 0x00000100u,
  MH_NOMULTIDEFS             = 0x00000200u,
  MH_NOFIXPREBINDING         = 0x00000400u,
  MH_PREBINDABLE             = 0x00000800u,
  MH_ALLMODSBOUND            = 0x00001000u,
  MH_SUBSECTIONS_VIA_SYMBOLS = 0x00002000u,
  MH_CANONICAL               = 0x00004000u,
  MH_WEAK_DEFINES            = 0x00008000u,
  MH_BINDS_TO_WEAK           = 0x00010000u,
  MH_ALLOW_STACK_EXECUTION   = 0x00020000u,
  MH_ROOT_SAFE               = 0x00040000u,
  MH_SETUID_SAFE             = 0x00080000u,
  MH_NO_REEXPORTED_DYLIBS    = 0x00100000u,
  MH_PIE                     = 0x00200000u,
  MH_DEAD_STRIPPABLE_DYLIB   = 0x00400000u,
  MH_HAS_TLV_DESCRIPTORS     = 0x00800000u,
  MH_NO_HEAP_EXECUTION       = 0x01000000u,
  MH_APP_EXTENSION_SAFE      = 0x02000000u
};


enum class LOAD_COMMAND_TYPES: size_t  {
  // Constants for the "cmd" field in llvm::MachO::load_command
  LC_SEGMENT                  = 0x00000001u,
  LC_SYMTAB                   = 0x00000002u,
  LC_SYMSEG                   = 0x00000003u,
  LC_THREAD                   = 0x00000004u,
  LC_UNIXTHREAD               = 0x00000005u,
  LC_LOADFVMLIB               = 0x00000006u,
  LC_IDFVMLIB                 = 0x00000007u,
  LC_IDENT                    = 0x00000008u,
  LC_FVMFILE                  = 0x00000009u,
  LC_PREPAGE                  = 0x0000000Au,
  LC_DYSYMTAB                 = 0x0000000Bu,
  LC_LOAD_DYLIB               = 0x0000000Cu,
  LC_ID_DYLIB                 = 0x0000000Du,
  LC_LOAD_DYLINKER            = 0x0000000Eu,
  LC_ID_DYLINKER              = 0x0000000Fu,
  LC_PREBOUND_DYLIB           = 0x00000010u,
  LC_ROUTINES                 = 0x00000011u,
  LC_SUB_FRAMEWORK            = 0x00000012u,
  LC_SUB_UMBRELLA             = 0x00000013u,
  LC_SUB_CLIENT               = 0x00000014u,
  LC_SUB_LIBRARY              = 0x00000015u,
  LC_TWOLEVEL_HINTS           = 0x00000016u,
  LC_PREBIND_CKSUM            = 0x00000017u,
  LC_LOAD_WEAK_DYLIB          = 0x80000018u,
  LC_SEGMENT_64               = 0x00000019u,
  LC_ROUTINES_64              = 0x0000001Au,
  LC_UUID                     = 0x0000001Bu,
  LC_RPATH                    = 0x8000001Cu,
  LC_CODE_SIGNATURE           = 0x0000001Du,
  LC_SEGMENT_SPLIT_INFO       = 0x0000001Eu,
  LC_REEXPORT_DYLIB           = 0x8000001Fu,
  LC_LAZY_LOAD_DYLIB          = 0x00000020u,
  LC_ENCRYPTION_INFO          = 0x00000021u,
  LC_DYLD_INFO                = 0x00000022u,
  LC_DYLD_INFO_ONLY           = 0x80000022u,
  LC_LOAD_UPWARD_DYLIB        = 0x80000023u,
  LC_VERSION_MIN_MACOSX       = 0x00000024u,
  LC_VERSION_MIN_IPHONEOS     = 0x00000025u,
  LC_FUNCTION_STARTS          = 0x00000026u,
  LC_DYLD_ENVIRONMENT         = 0x00000027u,
  LC_MAIN                     = 0x80000028u,
  LC_DATA_IN_CODE             = 0x00000029u,
  LC_SOURCE_VERSION           = 0x0000002Au,
  LC_DYLIB_CODE_SIGN_DRS      = 0x0000002Bu,
  LC_ENCRYPTION_INFO_64       = 0x0000002Cu,
  LC_LINKER_OPTION            = 0x0000002Du,
  LC_LINKER_OPTIMIZATION_HINT = 0x0000002Eu,
  LC_VERSION_MIN_TVOS         = 0x0000002Fu,
  LC_VERSION_MIN_WATCHOS      = 0x00000030u,
  LC_NOTE                     = 0x00000031u,
  LC_BUILD_VERSION            = 0x00000032u,
  LC_DYLD_EXPORTS_TRIE        = 0x80000033u,
  LC_DYLD_CHAINED_FIXUPS      = 0x80000034u,
  LC_FILESET_ENTRY            = 0x80000035u,
};


enum {
    // Flags for the "cmd" field in llvm::MachO::load_command
    LC_REQ_DYLD    = 0x80000000u
  };


enum class MACHO_SEGMENTS_FLAGS: size_t  {
  // Constant bits for the "flags" field in llvm::MachO::segment_command
  SG_HIGHVM              = 0x1u, ///< The file contents for this segment are for the high part of the virtual memory space; the low part is zero filled (for stacks in core files).
  SG_FVMLIB              = 0x2u, ///< this segment is the VM that is allocated by a fixed VM library, for overlap checking in the link editor.
  SG_NORELOC             = 0x4u, ///< This segment has nothing that was relocated in it and nothing relocated to it. It may be safely replaced without relocation.
  SG_PROTECTED_VERSION_1 = 0x8u,
};

enum class SECTION_FLAGS_HELPER: size_t   {
  // Constant masks for the "flags" field in llvm::MachO::section and
  // llvm::MachO::section_64
  SECTION_TYPE_MASK      = 0x000000ffu, // SECTION_TYPE
  SECTION_FLAGS_MASK     = 0xffffff00u, // SECTION_ATTRIBUTES
  SECTION_FLAGS_USR_MASK = 0xff000000u, // SECTION_ATTRIBUTES_USR
  SECTION_FLAGS_SYS_MASK = 0x00ffff00u  // SECTION_ATTRIBUTES_SYS
};

//! @brief These are the section type and attributes fields.  A MachO section can
//! have only one Type, but can have any of the attributes specified.
enum class MACHO_SECTION_TYPES: size_t  {
  // Constant masks for the "flags[7:0]" field in llvm::MachO::section and
  // llvm::MachO::section_64 (mask "flags" with SECTION_TYPE)
  S_REGULAR                             = 0x00u, ///< Regular section.
  S_ZEROFILL                            = 0x01u, ///< Zero fill on demand section.
  S_CSTRING_LITERALS                    = 0x02u, ///< Section with literal C strings.
  S_4BYTE_LITERALS                      = 0x03u, ///< Section with 4 byte literals.
  S_8BYTE_LITERALS                      = 0x04u, ///< Section with 8 byte literals.
  S_LITERAL_POINTERS                    = 0x05u, ///< Section with pointers to literals.
  S_NON_LAZY_SYMBOL_POINTERS            = 0x06u, ///< Section with non-lazy symbol pointers.
  S_LAZY_SYMBOL_POINTERS                = 0x07u, ///< Section with lazy symbol pointers.
  S_SYMBOL_STUBS                        = 0x08u, ///< Section with symbol stubs, byte size of stub in the Reserved2 field.
  S_MOD_INIT_FUNC_POINTERS              = 0x09u, ///< Section with only function pointers for initialization.
  S_MOD_TERM_FUNC_POINTERS              = 0x0au, ///< Section with only function pointers for termination.
  S_COALESCED                           = 0x0bu, ///< Section contains symbols that are to be coalesced.
  S_GB_ZEROFILL                         = 0x0cu, ///< Zero fill on demand section (that can be larger than 4 gigabytes).
  S_INTERPOSING                         = 0x0du, ///< Section with only pairs of function pointers for interposing.
  S_16BYTE_LITERALS                     = 0x0eu, ///< Section with only 16 byte literals.
  S_DTRACE_DOF                          = 0x0fu, ///< Section contains DTrace Object Format.
  S_LAZY_DYLIB_SYMBOL_POINTERS          = 0x10u, ///< Section with lazy symbol pointers to lazy loaded dylibs.
  S_THREAD_LOCAL_REGULAR                = 0x11u, ///< Thread local data section.
  S_THREAD_LOCAL_ZEROFILL               = 0x12u, ///< Thread local zerofill section.
  S_THREAD_LOCAL_VARIABLES              = 0x13u, ///< Section with thread local variable structure data.
  S_THREAD_LOCAL_VARIABLE_POINTERS      = 0x14u, ///< Section with pointers to thread local structures.
  S_THREAD_LOCAL_INIT_FUNCTION_POINTERS = 0x15u, ///< Section with thread local variable initialization pointers to functions.

  LAST_KNOWN_SECTION_TYPE = 0x15u, //S_THREAD_LOCAL_INIT_FUNCTION_POINTERS
};

enum class MACHO_SECTION_FLAGS: size_t  {

  // Constant masks for the "flags[31:24]" field in llvm::MachO::section and
  // llvm::MachO::section_64 (mask "flags" with SECTION_ATTRIBUTES_USR)
  S_ATTR_PURE_INSTRUCTIONS   = 0x80000000u, ///< Section contains only true machine instructions
  S_ATTR_NO_TOC              = 0x40000000u, ///< Section contains coalesced symbols that are not to be in a ranlib table of contents.
  S_ATTR_STRIP_STATIC_SYMS   = 0x20000000u, ///< Ok to strip static symbols in this section in files with the MY_DYLDLINK flag.
  S_ATTR_NO_DEAD_STRIP       = 0x10000000u, ///< No dead stripping.
  S_ATTR_LIVE_SUPPORT        = 0x08000000u, ///< Blocks are live if they reference live blocks.
  S_ATTR_SELF_MODIFYING_CODE = 0x04000000u, ///< Used with i386 code stubs written on by dyld
  S_ATTR_DEBUG               = 0x02000000u, ///< A debug section.

  // Constant masks for the "flags[23:8]" field in llvm::MachO::section and
  // llvm::MachO::section_64 (mask "flags" with SECTION_ATTRIBUTES_SYS)
  S_ATTR_SOME_INSTRUCTIONS   = 0x00000400u, ///< Section contains some machine instructions.
  S_ATTR_EXT_RELOC           = 0x00000200u, ///< Section has external relocation entries.
  S_ATTR_LOC_RELOC           = 0x00000100u, ///< Section has local relocation entries.

  // Constant masks for the value of an indirect symbol in an indirect
  // symbol table
  INDIRECT_SYMBOL_LOCAL = 0x80000000u,
  INDIRECT_SYMBOL_ABS   = 0x40000000u
};


enum class DataRegionType: size_t  {
  // Constants for the "kind" field in a data_in_code_entry structure
  DICE_KIND_DATA             = 1u,
  DICE_KIND_JUMP_TABLE8      = 2u,
  DICE_KIND_JUMP_TABLE16     = 3u,
  DICE_KIND_JUMP_TABLE32     = 4u,
  DICE_KIND_ABS_JUMP_TABLE32 = 5u
};

enum class REBASE_TYPES: size_t  {
  REBASE_TYPE_POINTER         = 1u,
  REBASE_TYPE_TEXT_ABSOLUTE32 = 2u,
  REBASE_TYPE_TEXT_PCREL32    = 3u,
  REBASE_TYPE_THREADED        = 102u,
};

enum {
  REBASE_OPCODE_MASK    = 0xF0u,
  REBASE_IMMEDIATE_MASK = 0x0Fu
};


//! @brief Opcodes used by Dyld info to rebase a Mach-O image
enum class REBASE_OPCODES: uint8_t {
  REBASE_OPCODE_DONE                               = 0x00u, ///< It's finished
  REBASE_OPCODE_SET_TYPE_IMM                       = 0x10u, ///< Set type to immediate (lower 4-bits). Used for ordinal numbers from 0-15
  REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB        = 0x20u, ///< Set segment's index to immediate (lower 4-bits) and segment's offset to following ULEB128 encoding.
  REBASE_OPCODE_ADD_ADDR_ULEB                      = 0x30u, ///< Add segment's offset with the following ULEB128 encoding.
  REBASE_OPCODE_ADD_ADDR_IMM_SCALED                = 0x40u, ///< Add segment's offset with immediate scaling
  REBASE_OPCODE_DO_REBASE_IMM_TIMES                = 0x50u, ///< Rebase in the range of ``[segment's offset; segment's offset + immediate * sizeof(ptr)]``
  REBASE_OPCODE_DO_REBASE_ULEB_TIMES               = 0x60u, ///< Same as REBASE_OPCODE_DO_REBASE_IMM_TIMES but *immediate* is replaced with ULEB128 value
  REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB            = 0x70u, ///< Rebase and increment segment's offset with following ULEB128 encoding + pointer's size
  REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = 0x80u  ///< Rebase and skip several bytes
};


//! @brief Within the dyld_info_command there are
//! differents area of binding. These enums
//! tag these area
enum class BINDING_CLASS: size_t  {
  BIND_CLASS_WEAK     = 1u,
  BIND_CLASS_LAZY     = 2u,
  BIND_CLASS_STANDARD = 3u,
  BIND_CLASS_THREADED = 100u
};


enum class BIND_TYPES: size_t  {
  BIND_TYPE_POINTER         = 1u,
  BIND_TYPE_TEXT_ABSOLUTE32 = 2u,
  BIND_TYPE_TEXT_PCREL32    = 3u
};

enum class BIND_SPECIAL_DYLIB: int {
  BIND_SPECIAL_DYLIB_SELF            =  0,
  BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE = -1,
  BIND_SPECIAL_DYLIB_FLAT_LOOKUP     = -2
};

enum {
  BIND_SYMBOL_FLAGS_WEAK_IMPORT         = 0x1u,
  BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION = 0x8u,

  BIND_OPCODE_MASK                      = 0xF0u,
  BIND_IMMEDIATE_MASK                   = 0x0Fu
};

//! @brief Opcodes used by Dyld info to bind symbols
enum class BIND_OPCODES: uint8_t {
  BIND_OPCODE_DONE                             = 0x00u, ///< It's finished
  BIND_OPCODE_SET_DYLIB_ORDINAL_IMM            = 0x10u, ///< Set ordinal to immediate (lower 4-bits). Used for ordinal numbers from 0-15
  BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB           = 0x20u, ///< Set ordinal to following ULEB128 encoding. Used for ordinal numbers from 16+
  BIND_OPCODE_SET_DYLIB_SPECIAL_IMM            = 0x30u, ///< Set ordinal, with 0 or negative number as immediate. the value is sign extended.
  BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM    = 0x40u, ///< Set the following symbol (NULL-terminated char*).
  BIND_OPCODE_SET_TYPE_IMM                     = 0x50u, ///< Set the type to immediate (lower 4-bits). See BIND_TYPES
  BIND_OPCODE_SET_ADDEND_SLEB                  = 0x60u, ///< Set the addend field to the following SLEB128 encoding.
  BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB      = 0x70u, ///< Set Segment to immediate value, and address to the following SLEB128 encoding
  BIND_OPCODE_ADD_ADDR_ULEB                    = 0x80u, ///< Set the address field to the following SLEB128 encoding.
  BIND_OPCODE_DO_BIND                          = 0x90u, ///< Perform binding of current table row
  BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB            = 0xA0u, ///< Perform binding, also add following ULEB128 as address
  BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED      = 0xB0u, ///< Perform binding, also add immediate (lower 4-bits) using scaling
  BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0u, ///< Perform binding for several symbols (as following ULEB128), and skip several bytes.
  BIND_OPCODE_THREADED                         = 0xD0u,

  BIND_OPCODE_THREADED_APPLY                            = 0xD0u | 0x01u,
  BIND_OPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB = 0xD0u | 0x00u,
};

enum class BIND_SUBOPCODE_THREADED: uint8_t {
  BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB = 0x00u,
  BIND_SUBOPCODE_THREADED_APPLY                            = 0x01u,
};

enum class EXPORT_SYMBOL_FLAGS: size_t  {
  EXPORT_SYMBOL_FLAGS_KIND_MASK           = 0x03u, ///< Mask to access to EXPORT_SYMBOL_KINDS
  EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION     = 0x04u,
  EXPORT_SYMBOL_FLAGS_REEXPORT            = 0x08u,
  EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER   = 0x10u
};

enum class EXPORT_SYMBOL_KINDS: size_t  {
  EXPORT_SYMBOL_FLAGS_KIND_REGULAR        = 0x00u,
  EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL   = 0x01u,
  EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE       = 0x02u
};

enum class MACHO_SYMBOL_TYPES: size_t  {
  N_STAB = 0xe0, ///< The symbol is symbolic debugging table
  N_PEXT = 0x10, ///< Limited global scope symbol.
  N_TYPE = 0x0e, ///< Define the type of the symbol. @see N_LIST_TYPES
  N_EXT  = 0x01  ///< External symbol, a symbol that is either defined outside this file or that is defined in this file but can be referenced by other files.
};

//! @brief Constants for the "n_type & SYMBOL_TYPES::N_TYPE" in nlist
//! @see nlist
enum class N_LIST_TYPES: size_t  {
  N_UNDF = 0x0u, ///< The symbol is undefined. It is referenced in a different module.
  N_ABS  = 0x2u, ///< The symbol is absolute. The linker doesn't update his value.
  N_SECT = 0xeu, ///< The symbol is defined in the section number given in nlist_base.n_sect .
  N_PBUD = 0xcu, ///< The symbol is undefined and the image is using a prebound value for the symbol. Set the n_sect field to NO_SECT .
  N_INDR = 0xau  ///< The symbol is defined to be the same as another symbol. The n_value field is an index into the string table specifying the name of the other symbol. When that symbol is linked, both this and the other symbol point to the same defined type and value.
};

enum class SectionOrdinal: size_t  {
  // Constants for the "n_sect" field in llvm::MachO::nlist and
  // llvm::MachO::nlist_64
  NO_SECT  = 0u,
  MAX_SECT = 0xffu
};

enum class SYMBOL_DESCRIPTIONS: size_t  {

  // The low 3 bits are the for the REFERENCE_TYPE.
  REFERENCE_TYPE                            = 0x7,
  REFERENCE_FLAG_UNDEFINED_NON_LAZY         = 0, ///< Reference to an external non-lazy (data) symbol.
  REFERENCE_FLAG_UNDEFINED_LAZY             = 1, ///< Reference to an external lazy symbol - that is, to a function call.
  REFERENCE_FLAG_DEFINED                    = 2, ///< Defined in this module.
  REFERENCE_FLAG_PRIVATE_DEFINED            = 3, ///< Defined in this module and is visible only to modules within this shared library.
  REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY = 4, ///< Defined in another module in this file, is a non-lazy (data) symbol, and is visible only to modules within this shared library.
  REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY     = 5, ///< Defined in another module in this file, is a lazy (function) symbol, and is visible only to modules within this shared library.

  // Flag bits (some overlap with the library ordinal bits).
  N_ARM_THUMB_DEF        = 0x0008u,
  REFERENCED_DYNAMICALLY = 0x0010u,
  N_NO_DEAD_STRIP        = 0x0020u,
  N_WEAK_REF             = 0x0040u,
  N_WEAK_DEF             = 0x0080u,
  N_SYMBOL_RESOLVER      = 0x0100u,
  N_ALT_ENTRY            = 0x0200u,

  // For undefined symbols coming from libraries, see GET_LIBRARY_ORDINAL()
  // as these are in the top 8 bits.
  SELF_LIBRARY_ORDINAL   = 0x0,
  MAX_LIBRARY_ORDINAL    = 0xfd,
  DYNAMIC_LOOKUP_ORDINAL = 0xfe,
  EXECUTABLE_ORDINAL     = 0xff
};

enum class StabType: size_t  {
  // Constant values for the "n_type" field in llvm::MachO::nlist and
  // llvm::MachO::nlist_64 when "(n_type & N_STAB) != 0"
  N_GSYM    = 0x20u,
  N_FNAME   = 0x22u,
  N_FUN     = 0x24u,
  N_STSYM   = 0x26u,
  N_LCSYM   = 0x28u,
  N_BNSYM   = 0x2Eu,
  N_PC      = 0x30u,
  N_AST     = 0x32u,
  N_OPT     = 0x3Cu,
  N_RSYM    = 0x40u,
  N_SLINE   = 0x44u,
  N_ENSYM   = 0x4Eu,
  N_SSYM    = 0x60u,
  N_SO      = 0x64u,
  N_OSO     = 0x66u,
  N_LSYM    = 0x80u,
  N_BINCL   = 0x82u,
  N_SOL     = 0x84u,
  N_PARAMS  = 0x86u,
  N_VERSION = 0x88u,
  N_OLEVEL  = 0x8Au,
  N_PSYM    = 0xA0u,
  N_EINCL   = 0xA2u,
  N_ENTRY   = 0xA4u,
  N_LBRAC   = 0xC0u,
  N_EXCL    = 0xC2u,
  N_RBRAC   = 0xE0u,
  N_BCOMM   = 0xE2u,
  N_ECOMM   = 0xE4u,
  N_ECOML   = 0xE8u,
  N_LENG    = 0xFEu
};


enum {
  // Constant values for the r_symbolnum field in an
  // llvm::MachO::relocation_info structure when r_extern is 0.
  R_ABS = 0,

  // Constant bits for the r_address field in an
  // llvm::MachO::relocation_info structure.
  R_SCATTERED = 0x80000000
};

enum class RELOCATION_ORIGINS: size_t  {
  ORIGIN_UNKNOWN     = 0,
  ORIGIN_DYLDINFO    = 1,
  ORIGIN_RELOC_TABLE = 2,
};


enum class SYMBOL_ORIGINS: size_t  {
  SYM_ORIGIN_UNKNOWN     = 0,
  SYM_ORIGIN_DYLD_EXPORT = 1,
  SYM_ORIGIN_DYLD_BIND   = 2, /// The symbol comes from the binding opcodes
  SYM_ORIGIN_LC_SYMTAB   = 3,
};

enum class X86_RELOCATION: size_t  {
  GENERIC_RELOC_VANILLA        = 0, /**< A generic relocation entry for both addresses contained in data and addresses contained in CPU instructions. */
  GENERIC_RELOC_PAIR           = 1, /**< The second relocation entry of a pair. */
  GENERIC_RELOC_SECTDIFF       = 2, /**< A relocation entry for an item that contains the difference of two section addresses. This is generally used for position-independent code generation. */
  GENERIC_RELOC_PB_LA_PTR      = 3, /**< contains the address from which to subtract; it must be followed by a X86_RELOCATION::GENERIC_RELOC_PAIR containing the address to subtract.*/
  GENERIC_RELOC_LOCAL_SECTDIFF = 4, /**< Similar to X86_RELOCATION::GENERIC_RELOC_SECTDIFF except that this entry refers specifically to the address in this item. If the address is that of a globally visible coalesced symbol, this relocation entry does not change if the symbol is overridden. This is used to associate stack unwinding information with the object code this relocation entry describes.*/
  GENERIC_RELOC_TLV            = 5, /**< A relocation entry for a prebound lazy pointer. This is always a scattered relocation entry. The MachO::Relocation::value field contains the non-prebound value of the lazy pointer.*/
};


enum class X86_64_RELOCATION: size_t  {
  X86_64_RELOC_UNSIGNED        = 0, /**< A CALL/JMP instruction with 32-bit displacement. */
  X86_64_RELOC_SIGNED          = 1, /**< A MOVQ load of a GOT entry. */
  X86_64_RELOC_BRANCH          = 2, /**< Other GOT references. */
  X86_64_RELOC_GOT_LOAD        = 3, /**< Signed 32-bit displacement. */
  X86_64_RELOC_GOT             = 4, /**< Absolute address. */
  X86_64_RELOC_SUBTRACTOR      = 5, /**< Must be followed by a X86_64_RELOCATION::X86_64_RELOC_UNSIGNED relocation. */
  X86_64_RELOC_SIGNED_1        = 6, /**< */
  X86_64_RELOC_SIGNED_2        = 7, /**< */
  X86_64_RELOC_SIGNED_4        = 8, /**< */
  X86_64_RELOC_TLV             = 9, /**< */
};


enum class PPC_RELOCATION: size_t  {
  PPC_RELOC_VANILLA            = 0,
  PPC_RELOC_PAIR               = 1,
  PPC_RELOC_BR14               = 2,
  PPC_RELOC_BR24               = 3,
  PPC_RELOC_HI16               = 4,
  PPC_RELOC_LO16               = 5,
  PPC_RELOC_HA16               = 6,
  PPC_RELOC_LO14               = 7,
  PPC_RELOC_SECTDIFF           = 8,
  PPC_RELOC_PB_LA_PTR          = 9,
  PPC_RELOC_HI16_SECTDIFF      = 10,
  PPC_RELOC_LO16_SECTDIFF      = 11,
  PPC_RELOC_HA16_SECTDIFF      = 12,
  PPC_RELOC_JBSR               = 13,
  PPC_RELOC_LO14_SECTDIFF      = 14,
  PPC_RELOC_LOCAL_SECTDIFF     = 15,
};


enum class ARM_RELOCATION: size_t  {
  ARM_RELOC_VANILLA            = 0,
  ARM_RELOC_PAIR               = 1,
  ARM_RELOC_SECTDIFF           = 2,
  ARM_RELOC_LOCAL_SECTDIFF     = 3,
  ARM_RELOC_PB_LA_PTR          = 4,
  ARM_RELOC_BR24               = 5,
  ARM_THUMB_RELOC_BR22         = 6,
  ARM_THUMB_32BIT_BRANCH       = 7, // obsolete
  ARM_RELOC_HALF               = 8,
  ARM_RELOC_HALF_SECTDIFF      = 9,
};


enum class ARM64_RELOCATION: size_t  {
  ARM64_RELOC_UNSIGNED            = 0,  /**< For pointers. */
  ARM64_RELOC_SUBTRACTOR          = 1,  /**< Must be followed by an ARM64_RELOCATION::ARM64_RELOC_UNSIGNED */
  ARM64_RELOC_BRANCH26            = 2,  /**< A B/BL instruction with 26-bit displacement. */
  ARM64_RELOC_PAGE21              = 3,  /**< PC-rel distance to page of target. */
  ARM64_RELOC_PAGEOFF12           = 4,  /**< Offset within page, scaled by MachO::Relocation::size. */
  ARM64_RELOC_GOT_LOAD_PAGE21     = 5,  /**< PC-rel distance to page of GOT slot */
  ARM64_RELOC_GOT_LOAD_PAGEOFF12  = 6,  /**< Offset within page of GOT slot, scaled by MachO::Relocation::size. */
  ARM64_RELOC_POINTER_TO_GOT      = 7,  /**< For pointers to GOT slots. */
  ARM64_RELOC_TLVP_LOAD_PAGE21    = 8,  /**< PC-rel distance to page of TLVP slot. */
  ARM64_RELOC_TLVP_LOAD_PAGEOFF12 = 9,  /**< Offset within page of TLVP slot, scaled by MachO::Relocation::size.*/
  ARM64_RELOC_ADDEND              = 10, /**< Must be followed by ARM64_RELOCATION::ARM64_RELOC_PAGE21 or ARM64_RELOCATION::ARM64_RELOC_PAGEOFF12. */
};

//! Values for segment_command.initprot.
//! From <mach/vm_prot.h>
enum class VM_PROTECTIONS: size_t  {
  VM_PROT_READ    = 0x1, ///< Reading data within the segment is allowed
  VM_PROT_WRITE   = 0x2, ///< Writing data within the segment is allowed
  VM_PROT_EXECUTE = 0x4, ///< Executing data within the segment is allowed
};


// Enums from <mach/machine.h>
enum {
  // Capability bits used in the definition of cpu_type.
  CPU_ARCH_MASK  = 0xff000000,   // Mask for architecture bits
  CPU_ARCH_ABI64 = 0x01000000    // 64 bit ABI
};

// Constants for the cputype field.
enum class CPU_TYPES: int {
  CPU_TYPE_ANY       = -1,
  CPU_TYPE_X86       = 7,
  CPU_TYPE_I386      = 7,              // CPU_TYPE_X86,
  CPU_TYPE_X86_64    = 7 | 0x01000000, // CPU_TYPE_X86 | CPU_ARCH_ABI64,
/* CPU_TYPE_MIPS      = 8, */
  CPU_TYPE_MC98000   = 10, // Old Motorola PowerPC
  CPU_TYPE_ARM       = 12,
  CPU_TYPE_ARM64     = 12 | 0x01000000, // CPU_TYPE_ARM | CPU_ARCH_ABI64,
  CPU_TYPE_SPARC     = 14,
  CPU_TYPE_POWERPC   = 18,
  CPU_TYPE_POWERPC64 = 18 | 0x01000000, // CPU_TYPE_POWERPC | CPU_ARCH_ABI64
};

enum {
  // Capability bits used in the definition of cpusubtype.
  CPU_SUBTYPE_MASK  = 0xff000000,   // Mask for architecture bits
  CPU_SUBTYPE_LIB64 = 0x80000000,   // 64 bit libraries

  // Special CPU subtype constants.
  CPU_SUBTYPE_MULTIPLE = ~0u
};

// Constants for the cpusubtype field.
enum class CPU_SUBTYPES_X86: size_t  {
  CPU_SUBTYPE_I386_ALL       = 3,
  CPU_SUBTYPE_386            = 3,
  CPU_SUBTYPE_486            = 4,
  CPU_SUBTYPE_486SX          = 0x84,
  CPU_SUBTYPE_586            = 5,
  CPU_SUBTYPE_PENT           = 5, // CPU_SUBTYPE_586,
  CPU_SUBTYPE_PENTPRO        = 0x16,
  CPU_SUBTYPE_PENTII_M3      = 0x36,
  CPU_SUBTYPE_PENTII_M5      = 0x56,
  CPU_SUBTYPE_CELERON        = 0x67,
  CPU_SUBTYPE_CELERON_MOBILE = 0x77,
  CPU_SUBTYPE_PENTIUM_3      = 0x08,
  CPU_SUBTYPE_PENTIUM_3_M    = 0x18,
  CPU_SUBTYPE_PENTIUM_3_XEON = 0x28,
  CPU_SUBTYPE_PENTIUM_M      = 0x09,
  CPU_SUBTYPE_PENTIUM_4      = 0x0a,
  CPU_SUBTYPE_PENTIUM_4_M    = 0x1a,
  CPU_SUBTYPE_ITANIUM        = 0x0b,
  CPU_SUBTYPE_ITANIUM_2      = 0x1b,
  CPU_SUBTYPE_XEON           = 0x0c,
  CPU_SUBTYPE_XEON_MP        = 0x1c,

  CPU_SUBTYPE_X86_ALL     = 3,
  CPU_SUBTYPE_X86_64_ALL  = 3,
  CPU_SUBTYPE_X86_ARCH1   = 4,
  CPU_SUBTYPE_X86_64_H    = 8
};


enum {
  CPU_SUBTYPE_INTEL_FAMILY_MAX = 15,
  CPU_SUBTYPE_INTEL_MODEL_ALL  = 0
};

enum class CPU_SUBTYPES_ARM: size_t  {
  CPU_SUBTYPE_ARM_ALL     = 0,
  CPU_SUBTYPE_ARM_V4T     = 5,
  CPU_SUBTYPE_ARM_V6      = 6,
  CPU_SUBTYPE_ARM_V5      = 7,
  CPU_SUBTYPE_ARM_V5TEJ   = 7,
  CPU_SUBTYPE_ARM_XSCALE  = 8,
  CPU_SUBTYPE_ARM_V7      = 9,
  //  unused  ARM_V7F     = 10,
  CPU_SUBTYPE_ARM_V7S     = 11,
  CPU_SUBTYPE_ARM_V7K     = 12,
  CPU_SUBTYPE_ARM_V6M     = 14,
  CPU_SUBTYPE_ARM_V7M     = 15,
  CPU_SUBTYPE_ARM_V7EM    = 16
};

enum class CPU_SUBTYPES_ARM64: size_t  {
  CPU_SUBTYPE_ARM64_ALL   = 0
};

enum class CPU_SUBTYPES_SPARC: size_t  {
  CPU_SUBTYPE_SPARC_ALL   = 0
};

enum class CPU_SUBTYPES_POWERPC: size_t  {
  CPU_SUBTYPE_POWERPC_ALL   = 0,
  CPU_SUBTYPE_POWERPC_601   = 1,
  CPU_SUBTYPE_POWERPC_602   = 2,
  CPU_SUBTYPE_POWERPC_603   = 3,
  CPU_SUBTYPE_POWERPC_603e  = 4,
  CPU_SUBTYPE_POWERPC_603ev = 5,
  CPU_SUBTYPE_POWERPC_604   = 6,
  CPU_SUBTYPE_POWERPC_604e  = 7,
  CPU_SUBTYPE_POWERPC_620   = 8,
  CPU_SUBTYPE_POWERPC_750   = 9,
  CPU_SUBTYPE_POWERPC_7400  = 10,
  CPU_SUBTYPE_POWERPC_7450  = 11,
  CPU_SUBTYPE_POWERPC_970   = 100,

  CPU_SUBTYPE_MC980000_ALL  = 0, //CPU_SUBTYPE_POWERPC_ALL,
  CPU_SUBTYPE_MC98601       = 1, //CPU_SUBTYPE_POWERPC_601
};

static const HEADER_FLAGS header_flags_array[] = {
  HEADER_FLAGS::MH_NOUNDEFS,              HEADER_FLAGS::MH_INCRLINK,
  HEADER_FLAGS::MH_DYLDLINK,              HEADER_FLAGS::MH_BINDATLOAD,
  HEADER_FLAGS::MH_PREBOUND,              HEADER_FLAGS::MH_SPLIT_SEGS,
  HEADER_FLAGS::MH_LAZY_INIT,             HEADER_FLAGS::MH_TWOLEVEL,
  HEADER_FLAGS::MH_FORCE_FLAT,            HEADER_FLAGS::MH_NOMULTIDEFS,
  HEADER_FLAGS::MH_NOFIXPREBINDING,       HEADER_FLAGS::MH_PREBINDABLE,
  HEADER_FLAGS::MH_ALLMODSBOUND,          HEADER_FLAGS::MH_SUBSECTIONS_VIA_SYMBOLS,
  HEADER_FLAGS::MH_CANONICAL,             HEADER_FLAGS::MH_WEAK_DEFINES,
  HEADER_FLAGS::MH_BINDS_TO_WEAK,         HEADER_FLAGS::MH_ALLOW_STACK_EXECUTION,
  HEADER_FLAGS::MH_ROOT_SAFE,             HEADER_FLAGS::MH_SETUID_SAFE,
  HEADER_FLAGS::MH_NO_REEXPORTED_DYLIBS,  HEADER_FLAGS::MH_PIE,
  HEADER_FLAGS::MH_DEAD_STRIPPABLE_DYLIB, HEADER_FLAGS::MH_HAS_TLV_DESCRIPTORS,
  HEADER_FLAGS::MH_NO_HEAP_EXECUTION,     HEADER_FLAGS::MH_APP_EXTENSION_SAFE
};


static const MACHO_SECTION_FLAGS section_flags_array[] = {
  MACHO_SECTION_FLAGS::S_ATTR_PURE_INSTRUCTIONS, MACHO_SECTION_FLAGS::S_ATTR_NO_TOC,
  MACHO_SECTION_FLAGS::S_ATTR_STRIP_STATIC_SYMS, MACHO_SECTION_FLAGS::S_ATTR_NO_DEAD_STRIP,
  MACHO_SECTION_FLAGS::S_ATTR_LIVE_SUPPORT,      MACHO_SECTION_FLAGS::S_ATTR_SELF_MODIFYING_CODE,
  MACHO_SECTION_FLAGS::S_ATTR_DEBUG,             MACHO_SECTION_FLAGS::S_ATTR_SOME_INSTRUCTIONS,
  MACHO_SECTION_FLAGS::S_ATTR_EXT_RELOC,         MACHO_SECTION_FLAGS::S_ATTR_LOC_RELOC
};

static const EXPORT_SYMBOL_FLAGS export_symbol_flags[] = {
  EXPORT_SYMBOL_FLAGS::EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION,
  EXPORT_SYMBOL_FLAGS::EXPORT_SYMBOL_FLAGS_REEXPORT,
  EXPORT_SYMBOL_FLAGS::EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER,
};

}
}

ENABLE_BITMASK_OPERATORS(LIEF::MachO::EXPORT_SYMBOL_FLAGS)
ENABLE_BITMASK_OPERATORS(LIEF::MachO::MACHO_SECTION_FLAGS)
ENABLE_BITMASK_OPERATORS(LIEF::MachO::HEADER_FLAGS)
ENABLE_BITMASK_OPERATORS(LIEF::MachO::REBASE_OPCODES)
ENABLE_BITMASK_OPERATORS(LIEF::MachO::BIND_OPCODES)
#endif
