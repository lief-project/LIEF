/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include "LIEF/MachO/enums.hpp"
#include "LIEF/MachO/EnumToString.hpp"
#include "frozen.hpp"

namespace LIEF {
namespace MachO {


const char* to_string(MACHO_TYPES e) {
  CONST_MAP(MACHO_TYPES, const char*, 6) enumStrings {
      { MACHO_TYPES::MH_MAGIC,    "MAGIC"},
      { MACHO_TYPES::MH_CIGAM,    "CIGAM"},
      { MACHO_TYPES::MH_MAGIC_64, "MAGIC_64"},
      { MACHO_TYPES::MH_CIGAM_64, "CIGAM_64"},
      { MACHO_TYPES::FAT_MAGIC,   "FAT_MAGIC"},
      { MACHO_TYPES::FAT_CIGAM,   "FAT_CIGAM"}
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(FILE_TYPES e) {
  CONST_MAP(FILE_TYPES, const char*, 11) enumStrings {
      { FILE_TYPES::MH_OBJECT,        "OBJECT"},
      { FILE_TYPES::MH_EXECUTE,       "EXECUTE"},
      { FILE_TYPES::MH_FVMLIB,        "FVMLIB"},
      { FILE_TYPES::MH_CORE,          "CORE"},
      { FILE_TYPES::MH_PRELOAD,       "PRELOAD"},
      { FILE_TYPES::MH_DYLIB,         "DYLIB"},
      { FILE_TYPES::MH_DYLINKER,      "DYLINKER"},
      { FILE_TYPES::MH_BUNDLE,        "BUNDLE"},
      { FILE_TYPES::MH_DYLIB_STUB,    "DYLIB_STUB"},
      { FILE_TYPES::MH_DSYM,          "DSYM"},
      { FILE_TYPES::MH_KEXT_BUNDLE,   "KEXT_BUNDLE"}
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(LOAD_COMMAND_TYPES e) {
  CONST_MAP(LOAD_COMMAND_TYPES, const char*, 54) enumStrings {
      { LOAD_COMMAND_TYPES::LC_SEGMENT,                  "SEGMENT"},
      { LOAD_COMMAND_TYPES::LC_SYMTAB,                   "SYMTAB"},
      { LOAD_COMMAND_TYPES::LC_SYMSEG,                   "SYMSEG"},
      { LOAD_COMMAND_TYPES::LC_THREAD,                   "THREAD"},
      { LOAD_COMMAND_TYPES::LC_UNIXTHREAD,               "UNIXTHREAD"},
      { LOAD_COMMAND_TYPES::LC_LOADFVMLIB,               "LOADFVMLIB"},
      { LOAD_COMMAND_TYPES::LC_IDFVMLIB,                 "IDFVMLIB"},
      { LOAD_COMMAND_TYPES::LC_IDENT,                    "IDENT"},
      { LOAD_COMMAND_TYPES::LC_FVMFILE,                  "FVMFILE"},
      { LOAD_COMMAND_TYPES::LC_PREPAGE,                  "PREPAGE"},
      { LOAD_COMMAND_TYPES::LC_DYSYMTAB,                 "DYSYMTAB"},
      { LOAD_COMMAND_TYPES::LC_LOAD_DYLIB,               "LOAD_DYLIB"},
      { LOAD_COMMAND_TYPES::LC_ID_DYLIB,                 "ID_DYLIB"},
      { LOAD_COMMAND_TYPES::LC_LOAD_DYLINKER,            "LOAD_DYLINKER"},
      { LOAD_COMMAND_TYPES::LC_ID_DYLINKER,              "ID_DYLINKER"},
      { LOAD_COMMAND_TYPES::LC_PREBOUND_DYLIB,           "PREBOUND_DYLIB"},
      { LOAD_COMMAND_TYPES::LC_ROUTINES,                 "ROUTINES"},
      { LOAD_COMMAND_TYPES::LC_SUB_FRAMEWORK,            "SUB_FRAMEWORK"},
      { LOAD_COMMAND_TYPES::LC_SUB_UMBRELLA,             "SUB_UMBRELLA"},
      { LOAD_COMMAND_TYPES::LC_SUB_CLIENT,               "SUB_CLIENT"},
      { LOAD_COMMAND_TYPES::LC_SUB_LIBRARY,              "SUB_LIBRARY"},
      { LOAD_COMMAND_TYPES::LC_TWOLEVEL_HINTS,           "TWOLEVEL_HINTS"},
      { LOAD_COMMAND_TYPES::LC_PREBIND_CKSUM,            "PREBIND_CKSUM"},
      { LOAD_COMMAND_TYPES::LC_LOAD_WEAK_DYLIB,          "LOAD_WEAK_DYLIB"},
      { LOAD_COMMAND_TYPES::LC_SEGMENT_64,               "SEGMENT_64"},
      { LOAD_COMMAND_TYPES::LC_ROUTINES_64,              "ROUTINES_64"},
      { LOAD_COMMAND_TYPES::LC_UUID,                     "UUID"},
      { LOAD_COMMAND_TYPES::LC_RPATH,                    "RPATH"},
      { LOAD_COMMAND_TYPES::LC_CODE_SIGNATURE,           "CODE_SIGNATURE"},
      { LOAD_COMMAND_TYPES::LC_SEGMENT_SPLIT_INFO,       "SEGMENT_SPLIT_INFO"},
      { LOAD_COMMAND_TYPES::LC_REEXPORT_DYLIB,           "REEXPORT_DYLIB"},
      { LOAD_COMMAND_TYPES::LC_LAZY_LOAD_DYLIB,          "LAZY_LOAD_DYLIB"},
      { LOAD_COMMAND_TYPES::LC_ENCRYPTION_INFO,          "ENCRYPTION_INFO"},
      { LOAD_COMMAND_TYPES::LC_DYLD_INFO,                "DYLD_INFO"},
      { LOAD_COMMAND_TYPES::LC_DYLD_INFO_ONLY,           "DYLD_INFO_ONLY"},
      { LOAD_COMMAND_TYPES::LC_LOAD_UPWARD_DYLIB,        "LOAD_UPWARD_DYLIB"},
      { LOAD_COMMAND_TYPES::LC_VERSION_MIN_MACOSX,       "VERSION_MIN_MACOSX"},
      { LOAD_COMMAND_TYPES::LC_VERSION_MIN_IPHONEOS,     "VERSION_MIN_IPHONEOS"},
      { LOAD_COMMAND_TYPES::LC_FUNCTION_STARTS,          "FUNCTION_STARTS"},
      { LOAD_COMMAND_TYPES::LC_DYLD_ENVIRONMENT,         "DYLD_ENVIRONMENT"},
      { LOAD_COMMAND_TYPES::LC_MAIN,                     "MAIN"},
      { LOAD_COMMAND_TYPES::LC_DATA_IN_CODE,             "DATA_IN_CODE"},
      { LOAD_COMMAND_TYPES::LC_SOURCE_VERSION,           "SOURCE_VERSION"},
      { LOAD_COMMAND_TYPES::LC_DYLIB_CODE_SIGN_DRS,      "DYLIB_CODE_SIGN_DRS"},
      { LOAD_COMMAND_TYPES::LC_ENCRYPTION_INFO_64,       "ENCRYPTION_INFO_64"},
      { LOAD_COMMAND_TYPES::LC_LINKER_OPTION,            "LINKER_OPTION"},
      { LOAD_COMMAND_TYPES::LC_LINKER_OPTIMIZATION_HINT, "LINKER_OPTIMIZATION_HINT"},
      { LOAD_COMMAND_TYPES::LC_VERSION_MIN_TVOS,         "VERSION_MIN_TVOS"},
      { LOAD_COMMAND_TYPES::LC_VERSION_MIN_WATCHOS,      "VERSION_MIN_WATCHOS"},
      { LOAD_COMMAND_TYPES::LC_NOTE,                     "NOTE"},
      { LOAD_COMMAND_TYPES::LC_BUILD_VERSION,            "BUILD_VERSION"},
      { LOAD_COMMAND_TYPES::LC_DYLD_EXPORTS_TRIE,        "DYLD_EXPORTS_TRIE"},
      { LOAD_COMMAND_TYPES::LC_DYLD_CHAINED_FIXUPS,      "DYLD_CHAINED_FIXUPS"},
      { LOAD_COMMAND_TYPES::LC_FILESET_ENTRY,            "FILESET_ENTRY"}
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(CPU_TYPES e) {
  CONST_MAP(CPU_TYPES, const char*, 9) enumStrings {
      { CPU_TYPES::CPU_TYPE_ANY,       "ANY"},
      { CPU_TYPES::CPU_TYPE_X86,       "x86"},
      //{ CPU_TYPES::CPU_TYPE_I386,      "i386"},
      { CPU_TYPES::CPU_TYPE_X86_64,    "x86_64"},
      //{ CPU_TYPES::CPU_TYPE_MIPS,      "MIPS"},
      { CPU_TYPES::CPU_TYPE_MC98000,   "MC98000"},
      { CPU_TYPES::CPU_TYPE_ARM,       "ARM"},
      { CPU_TYPES::CPU_TYPE_ARM64,     "ARM64"},
      { CPU_TYPES::CPU_TYPE_SPARC,     "SPARC"},
      { CPU_TYPES::CPU_TYPE_POWERPC,   "POWERPC"},
      { CPU_TYPES::CPU_TYPE_POWERPC64, "POWERPC64"}
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(HEADER_FLAGS e) {
  CONST_MAP(HEADER_FLAGS, const char*, 26) enumStrings {
      { HEADER_FLAGS::MH_NOUNDEFS                ,"NOUNDEFS"},
      { HEADER_FLAGS::MH_INCRLINK                ,"INCRLINK"},
      { HEADER_FLAGS::MH_DYLDLINK                ,"DYLDLINK"},
      { HEADER_FLAGS::MH_BINDATLOAD              ,"BINDATLOAD"},
      { HEADER_FLAGS::MH_PREBOUND                ,"PREBOUND"},
      { HEADER_FLAGS::MH_SPLIT_SEGS              ,"SPLIT_SEGS"},
      { HEADER_FLAGS::MH_LAZY_INIT               ,"LAZY_INIT"},
      { HEADER_FLAGS::MH_TWOLEVEL                ,"TWOLEVEL"},
      { HEADER_FLAGS::MH_FORCE_FLAT              ,"FORCE_FLAT"},
      { HEADER_FLAGS::MH_NOMULTIDEFS             ,"NOMULTIDEFS"},
      { HEADER_FLAGS::MH_NOFIXPREBINDING         ,"NOFIXPREBINDING"},
      { HEADER_FLAGS::MH_PREBINDABLE             ,"PREBINDABLE"},
      { HEADER_FLAGS::MH_ALLMODSBOUND            ,"ALLMODSBOUND"},
      { HEADER_FLAGS::MH_SUBSECTIONS_VIA_SYMBOLS ,"SUBSECTIONS_VIA_SYMBOLS"},
      { HEADER_FLAGS::MH_CANONICAL               ,"CANONICAL"},
      { HEADER_FLAGS::MH_WEAK_DEFINES            ,"WEAK_DEFINES"},
      { HEADER_FLAGS::MH_BINDS_TO_WEAK           ,"BINDS_TO_WEAK"},
      { HEADER_FLAGS::MH_ALLOW_STACK_EXECUTION   ,"ALLOW_STACK_EXECUTION"},
      { HEADER_FLAGS::MH_ROOT_SAFE               ,"ROOT_SAFE"},
      { HEADER_FLAGS::MH_SETUID_SAFE             ,"SETUID_SAFE"},
      { HEADER_FLAGS::MH_NO_REEXPORTED_DYLIBS    ,"NO_REEXPORTED_DYLIBS"},
      { HEADER_FLAGS::MH_PIE                     ,"PIE"},
      { HEADER_FLAGS::MH_DEAD_STRIPPABLE_DYLIB   ,"DEAD_STRIPPABLE_DYLIB"},
      { HEADER_FLAGS::MH_HAS_TLV_DESCRIPTORS     ,"HAS_TLV_DESCRIPTORS"},
      { HEADER_FLAGS::MH_NO_HEAP_EXECUTION       ,"NO_HEAP_EXECUTION"},
      { HEADER_FLAGS::MH_APP_EXTENSION_SAFE      ,"APP_EXTENSION_SAFE"}
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(MACHO_SECTION_TYPES e) {
  CONST_MAP(MACHO_SECTION_TYPES, const char*, 22) enumStrings {
      { MACHO_SECTION_TYPES::S_REGULAR,                             "REGULAR"},
      { MACHO_SECTION_TYPES::S_ZEROFILL,                            "ZEROFILL"},
      { MACHO_SECTION_TYPES::S_CSTRING_LITERALS,                    "CSTRING_LITERALS"},
      { MACHO_SECTION_TYPES::S_4BYTE_LITERALS,                      "S_4BYTE_LITERALS"},
      { MACHO_SECTION_TYPES::S_8BYTE_LITERALS,                      "S_8BYTE_LITERALS"},
      { MACHO_SECTION_TYPES::S_LITERAL_POINTERS,                    "LITERAL_POINTERS"},
      { MACHO_SECTION_TYPES::S_NON_LAZY_SYMBOL_POINTERS,            "NON_LAZY_SYMBOL_POINTERS"},
      { MACHO_SECTION_TYPES::S_LAZY_SYMBOL_POINTERS,                "LAZY_SYMBOL_POINTERS"},
      { MACHO_SECTION_TYPES::S_SYMBOL_STUBS,                        "SYMBOL_STUBS"},
      { MACHO_SECTION_TYPES::S_MOD_INIT_FUNC_POINTERS,              "MOD_INIT_FUNC_POINTERS"},
      { MACHO_SECTION_TYPES::S_MOD_TERM_FUNC_POINTERS,              "MOD_TERM_FUNC_POINTERS"},
      { MACHO_SECTION_TYPES::S_COALESCED,                           "COALESCED"},
      { MACHO_SECTION_TYPES::S_GB_ZEROFILL,                         "GB_ZEROFILL"},
      { MACHO_SECTION_TYPES::S_INTERPOSING,                         "INTERPOSING"},
      { MACHO_SECTION_TYPES::S_16BYTE_LITERALS,                     "S_16BYTE_LITERALS"},
      { MACHO_SECTION_TYPES::S_DTRACE_DOF,                          "DTRACE_DOF"},
      { MACHO_SECTION_TYPES::S_LAZY_DYLIB_SYMBOL_POINTERS,          "LAZY_DYLIB_SYMBOL_POINTERS"},
      { MACHO_SECTION_TYPES::S_THREAD_LOCAL_REGULAR,                "THREAD_LOCAL_REGULAR"},
      { MACHO_SECTION_TYPES::S_THREAD_LOCAL_ZEROFILL,               "THREAD_LOCAL_ZEROFILL"},
      { MACHO_SECTION_TYPES::S_THREAD_LOCAL_VARIABLES,              "THREAD_LOCAL_VARIABLES"},
      { MACHO_SECTION_TYPES::S_THREAD_LOCAL_VARIABLE_POINTERS,      "THREAD_LOCAL_VARIABLE_POINTERS"},
      { MACHO_SECTION_TYPES::S_THREAD_LOCAL_INIT_FUNCTION_POINTERS, "THREAD_LOCAL_INIT_FUNCTION_POINTERS"}
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(MACHO_SECTION_FLAGS e) {
  CONST_MAP(MACHO_SECTION_FLAGS, const char*, 10) enumStrings {
    { MACHO_SECTION_FLAGS::S_ATTR_PURE_INSTRUCTIONS,   "PURE_INSTRUCTIONS"},
    { MACHO_SECTION_FLAGS::S_ATTR_NO_TOC,              "NO_TOC"},
    { MACHO_SECTION_FLAGS::S_ATTR_STRIP_STATIC_SYMS,   "STRIP_STATIC_SYMS"},
    { MACHO_SECTION_FLAGS::S_ATTR_NO_DEAD_STRIP,       "NO_DEAD_STRIP"},
    { MACHO_SECTION_FLAGS::S_ATTR_LIVE_SUPPORT,        "LIVE_SUPPORT"},
    { MACHO_SECTION_FLAGS::S_ATTR_SELF_MODIFYING_CODE, "SELF_MODIFYING_CODE"},
    { MACHO_SECTION_FLAGS::S_ATTR_DEBUG,               "DEBUG"},
    { MACHO_SECTION_FLAGS::S_ATTR_SOME_INSTRUCTIONS,   "SOME_INSTRUCTIONS"},
    { MACHO_SECTION_FLAGS::S_ATTR_EXT_RELOC,           "EXT_RELOC"},
    { MACHO_SECTION_FLAGS::S_ATTR_LOC_RELOC,           "LOC_RELOC"}
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(MACHO_SYMBOL_TYPES e) {
  CONST_MAP(MACHO_SYMBOL_TYPES, const char*, 4) enumStrings {
    { MACHO_SYMBOL_TYPES::N_STAB, "STAB"},
    { MACHO_SYMBOL_TYPES::N_PEXT, "PEXT"},
    { MACHO_SYMBOL_TYPES::N_TYPE, "TYPE"},
    { MACHO_SYMBOL_TYPES::N_EXT,  "EXT"}
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(N_LIST_TYPES e) {
  CONST_MAP(N_LIST_TYPES, const char*, 5) enumStrings {
    { N_LIST_TYPES::N_UNDF, "UNDF"},
    { N_LIST_TYPES::N_ABS,  "ABS"},
    { N_LIST_TYPES::N_SECT, "SECT"},
    { N_LIST_TYPES::N_PBUD, "PBUD"},
    { N_LIST_TYPES::N_INDR, "INDR"}
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(SYMBOL_DESCRIPTIONS e) {
  CONST_MAP(SYMBOL_DESCRIPTIONS, const char*,  17) enumStrings {
    { SYMBOL_DESCRIPTIONS::REFERENCE_FLAG_UNDEFINED_NON_LAZY,         "FLAG_UNDEFINED_NON_LAZY"},
    { SYMBOL_DESCRIPTIONS::REFERENCE_FLAG_UNDEFINED_LAZY,             "FLAG_UNDEFINED_LAZY"},
    { SYMBOL_DESCRIPTIONS::REFERENCE_FLAG_DEFINED,                    "FLAG_DEFINED"},
    { SYMBOL_DESCRIPTIONS::REFERENCE_FLAG_PRIVATE_DEFINED,            "FLAG_PRIVATE_DEFINED"},
    { SYMBOL_DESCRIPTIONS::REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY, "FLAG_PRIVATE_UNDEFINED_NON_LAZY"},
    { SYMBOL_DESCRIPTIONS::REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY,     "FLAG_PRIVATE_UNDEFINED_LAZY"},
    { SYMBOL_DESCRIPTIONS::N_ARM_THUMB_DEF,                           "ARM_THUM"},
    { SYMBOL_DESCRIPTIONS::REFERENCED_DYNAMICALLY,                    "REFERENCED_DYNAMICALLY"},
    { SYMBOL_DESCRIPTIONS::N_NO_DEAD_STRIP,                           "NO_DEAD_STRIP"},
    { SYMBOL_DESCRIPTIONS::N_WEAK_REF,                                "WEAK_REF"},
    { SYMBOL_DESCRIPTIONS::N_WEAK_DEF,                                "WEAK_DEF"},
    { SYMBOL_DESCRIPTIONS::N_SYMBOL_RESOLVER,                         "SYMBOL_RESOLVER"},
    { SYMBOL_DESCRIPTIONS::N_ALT_ENTRY,                               "ALT_ENTRY"},
    { SYMBOL_DESCRIPTIONS::SELF_LIBRARY_ORDINAL,                      "SELF_LIBRARY_ORDINAL"},
    { SYMBOL_DESCRIPTIONS::MAX_LIBRARY_ORDINAL,                       "MAX_LIBRARY_ORDINAL"},
    { SYMBOL_DESCRIPTIONS::DYNAMIC_LOOKUP_ORDINAL,                    "DYNAMIC_LOOKUP_ORDINAL"},
    { SYMBOL_DESCRIPTIONS::EXECUTABLE_ORDINAL,                        "EXECUTABLE_ORDINAL"}
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(X86_RELOCATION e) {
  CONST_MAP(X86_RELOCATION, const char*, 6) enumStrings {
    { X86_RELOCATION::GENERIC_RELOC_VANILLA,        "VANILLA"        },
    { X86_RELOCATION::GENERIC_RELOC_PAIR,           "PAIR"           },
    { X86_RELOCATION::GENERIC_RELOC_SECTDIFF,       "SECTDIFF"       },
    { X86_RELOCATION::GENERIC_RELOC_PB_LA_PTR,      "PB_LA_PTR"      },
    { X86_RELOCATION::GENERIC_RELOC_LOCAL_SECTDIFF, "LOCAL_SECTDIFF" },
    { X86_RELOCATION::GENERIC_RELOC_TLV,            "TLV"            },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(X86_64_RELOCATION e) {
  CONST_MAP(X86_64_RELOCATION, const char*, 10) enumStrings {
    { X86_64_RELOCATION::X86_64_RELOC_UNSIGNED,   "UNSIGNED"   },
    { X86_64_RELOCATION::X86_64_RELOC_SIGNED,     "SIGNED"     },
    { X86_64_RELOCATION::X86_64_RELOC_BRANCH,     "BRANCH"     },
    { X86_64_RELOCATION::X86_64_RELOC_GOT_LOAD,   "GOT_LOAD"   },
    { X86_64_RELOCATION::X86_64_RELOC_GOT,        "GOT"        },
    { X86_64_RELOCATION::X86_64_RELOC_SUBTRACTOR, "SUBTRACTOR" },
    { X86_64_RELOCATION::X86_64_RELOC_SIGNED_1,   "SIGNED_1"   },
    { X86_64_RELOCATION::X86_64_RELOC_SIGNED_2,   "SIGNED_2"   },
    { X86_64_RELOCATION::X86_64_RELOC_SIGNED_4,   "SIGNED_4"   },
    { X86_64_RELOCATION::X86_64_RELOC_TLV,        "TLV"        },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(PPC_RELOCATION e) {
  CONST_MAP(PPC_RELOCATION, const char*, 16) enumStrings {
    { PPC_RELOCATION::PPC_RELOC_VANILLA,        "VANILLA"        },
    { PPC_RELOCATION::PPC_RELOC_PAIR,           "PAIR"           },
    { PPC_RELOCATION::PPC_RELOC_BR14,           "BR14"           },
    { PPC_RELOCATION::PPC_RELOC_BR24,           "BR24"           },
    { PPC_RELOCATION::PPC_RELOC_HI16,           "HI16"           },
    { PPC_RELOCATION::PPC_RELOC_LO16,           "LO16"           },
    { PPC_RELOCATION::PPC_RELOC_HA16,           "HA16"           },
    { PPC_RELOCATION::PPC_RELOC_LO14,           "LO14"           },
    { PPC_RELOCATION::PPC_RELOC_SECTDIFF,       "SECTDIFF"       },
    { PPC_RELOCATION::PPC_RELOC_PB_LA_PTR,      "PB_LA_PTR"      },
    { PPC_RELOCATION::PPC_RELOC_HI16_SECTDIFF,  "HI16_SECTDIFF"  },
    { PPC_RELOCATION::PPC_RELOC_LO16_SECTDIFF,  "LO16_SECTDIFF"  },
    { PPC_RELOCATION::PPC_RELOC_HA16_SECTDIFF,  "HA16_SECTDIFF"  },
    { PPC_RELOCATION::PPC_RELOC_JBSR,           "JBSR"           },
    { PPC_RELOCATION::PPC_RELOC_LO14_SECTDIFF,  "LO14_SECTDIFF"  },
    { PPC_RELOCATION::PPC_RELOC_LOCAL_SECTDIFF, "LOCAL_SECTDIFF" },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(ARM_RELOCATION e) {
  CONST_MAP(ARM_RELOCATION, const char*, 10) enumStrings {
    { ARM_RELOCATION::ARM_RELOC_VANILLA,        "VANILLA"        },
    { ARM_RELOCATION::ARM_RELOC_PAIR,           "PAIR"           },
    { ARM_RELOCATION::ARM_RELOC_SECTDIFF,       "SECTDIFF"       },
    { ARM_RELOCATION::ARM_RELOC_LOCAL_SECTDIFF, "LOCAL_SECTDIFF" },
    { ARM_RELOCATION::ARM_RELOC_PB_LA_PTR,      "PB_LA_PTR"      },
    { ARM_RELOCATION::ARM_RELOC_BR24,           "BR24"           },
    { ARM_RELOCATION::ARM_THUMB_RELOC_BR22,     "RELOC_BR22"     },
    { ARM_RELOCATION::ARM_THUMB_32BIT_BRANCH,   "32BIT_BRANCH"   },
    { ARM_RELOCATION::ARM_RELOC_HALF,           "HALF"           },
    { ARM_RELOCATION::ARM_RELOC_HALF_SECTDIFF,  "HALF_SECTDIFF"  },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(ARM64_RELOCATION e) {
  CONST_MAP(ARM64_RELOCATION, const char*, 11) enumStrings {
    { ARM64_RELOCATION::ARM64_RELOC_UNSIGNED,            "UNSIGNED"            },
    { ARM64_RELOCATION::ARM64_RELOC_SUBTRACTOR,          "SUBTRACTOR"          },
    { ARM64_RELOCATION::ARM64_RELOC_BRANCH26,            "BRANCH26"            },
    { ARM64_RELOCATION::ARM64_RELOC_PAGE21,              "PAGE21"              },
    { ARM64_RELOCATION::ARM64_RELOC_PAGEOFF12,           "PAGEOFF12"           },
    { ARM64_RELOCATION::ARM64_RELOC_GOT_LOAD_PAGE21,     "GOT_LOAD_PAGE21"     },
    { ARM64_RELOCATION::ARM64_RELOC_GOT_LOAD_PAGEOFF12,  "GOT_LOAD_PAGEOFF12"  },
    { ARM64_RELOCATION::ARM64_RELOC_POINTER_TO_GOT,      "POINTER_TO_GOT"      },
    { ARM64_RELOCATION::ARM64_RELOC_TLVP_LOAD_PAGE21,    "TLVP_LOAD_PAGE21"    },
    { ARM64_RELOCATION::ARM64_RELOC_TLVP_LOAD_PAGEOFF12, "TLVP_LOAD_PAGEOFF12" },
    { ARM64_RELOCATION::ARM64_RELOC_ADDEND,              "ADDEND"              },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(RELOCATION_ORIGINS e) {
  CONST_MAP(RELOCATION_ORIGINS, const char*, 3) enumStrings {
    { RELOCATION_ORIGINS::ORIGIN_UNKNOWN,     "UNKNOWN"     },
    { RELOCATION_ORIGINS::ORIGIN_DYLDINFO,    "DYLDINFO"    },
    { RELOCATION_ORIGINS::ORIGIN_RELOC_TABLE, "RELOC_TABLE" },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(REBASE_TYPES e) {
  CONST_MAP(REBASE_TYPES, const char*, 3) enumStrings {
    { REBASE_TYPES::REBASE_TYPE_POINTER,          "POINTER"         },
    { REBASE_TYPES::REBASE_TYPE_TEXT_ABSOLUTE32,  "TEXT_ABSOLUTE32" },
    { REBASE_TYPES::REBASE_TYPE_TEXT_PCREL32,     "TEXT_PCREL32"    },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(BINDING_CLASS e) {
  CONST_MAP(BINDING_CLASS, const char*, 4) enumStrings {
    { BINDING_CLASS::BIND_CLASS_WEAK,     "WEAK"      },
    { BINDING_CLASS::BIND_CLASS_LAZY,     "LAZY"      },
    { BINDING_CLASS::BIND_CLASS_STANDARD, "STANDARD"  },
    { BINDING_CLASS::BIND_CLASS_THREADED, "THREADED"  },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(REBASE_OPCODES e) {
  CONST_MAP(REBASE_OPCODES, const char*, 9) enumStrings {
    { REBASE_OPCODES::REBASE_OPCODE_DONE,                               "DONE"                               },
    { REBASE_OPCODES::REBASE_OPCODE_SET_TYPE_IMM,                       "SET_TYPE_IMM"                       },
    { REBASE_OPCODES::REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,        "SET_SEGMENT_AND_OFFSET_ULEB"        },
    { REBASE_OPCODES::REBASE_OPCODE_ADD_ADDR_ULEB,                      "ADD_ADDR_ULEB"                      },
    { REBASE_OPCODES::REBASE_OPCODE_ADD_ADDR_IMM_SCALED,                "ADD_ADDR_IMM_SCALED"                },
    { REBASE_OPCODES::REBASE_OPCODE_DO_REBASE_IMM_TIMES,                "DO_REBASE_IMM_TIMES"                },
    { REBASE_OPCODES::REBASE_OPCODE_DO_REBASE_ULEB_TIMES,               "DO_REBASE_ULEB_TIMES"               },
    { REBASE_OPCODES::REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB,            "DO_REBASE_ADD_ADDR_ULEB"            },
    { REBASE_OPCODES::REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB, "DO_REBASE_ULEB_TIMES_SKIPPING_ULEB" },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(BIND_TYPES e) {
  CONST_MAP(BIND_TYPES, const char*, 3) enumStrings {
    { BIND_TYPES::BIND_TYPE_POINTER,         "POINTER"         },
    { BIND_TYPES::BIND_TYPE_TEXT_ABSOLUTE32, "TEXT_ABSOLUTE32" },
    { BIND_TYPES::BIND_TYPE_TEXT_PCREL32,    "TEXT_PCREL32"    },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(BIND_SPECIAL_DYLIB e) {
  CONST_MAP(BIND_SPECIAL_DYLIB, const char*, 3) enumStrings {
    { BIND_SPECIAL_DYLIB::BIND_SPECIAL_DYLIB_SELF,            "SELF"            },
    { BIND_SPECIAL_DYLIB::BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE, "MAIN_EXECUTABLE" },
    { BIND_SPECIAL_DYLIB::BIND_SPECIAL_DYLIB_FLAT_LOOKUP,     "FLAT_LOOKUP"     },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(BIND_OPCODES e) {
  CONST_MAP(BIND_OPCODES, const char*, 14) enumStrings {
    { BIND_OPCODES::BIND_OPCODE_DONE,                             "DONE"                             },
    { BIND_OPCODES::BIND_OPCODE_SET_DYLIB_ORDINAL_IMM,            "SET_DYLIB_ORDINAL_IMM"            },
    { BIND_OPCODES::BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB,           "SET_DYLIB_ORDINAL_ULEB"           },
    { BIND_OPCODES::BIND_OPCODE_SET_DYLIB_SPECIAL_IMM,            "SET_DYLIB_SPECIAL_IMM"            },
    { BIND_OPCODES::BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM,    "SET_SYMBOL_TRAILING_FLAGS_IMM"    },
    { BIND_OPCODES::BIND_OPCODE_SET_TYPE_IMM,                     "SET_TYPE_IMM"                     },
    { BIND_OPCODES::BIND_OPCODE_SET_ADDEND_SLEB,                  "SET_ADDEND_SLEB"                  },
    { BIND_OPCODES::BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,      "SET_SEGMENT_AND_OFFSET_ULEB"      },
    { BIND_OPCODES::BIND_OPCODE_ADD_ADDR_ULEB,                    "ADD_ADDR_ULEB"                    },
    { BIND_OPCODES::BIND_OPCODE_DO_BIND,                          "DO_BIND"                          },
    { BIND_OPCODES::BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB,            "DO_BIND_ADD_ADDR_ULEB"            },
    { BIND_OPCODES::BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED,      "DO_BIND_ADD_ADDR_IMM_SCALED"      },
    { BIND_OPCODES::BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB, "DO_BIND_ULEB_TIMES_SKIPPING_ULEB" },
    { BIND_OPCODES::BIND_OPCODE_THREADED,                         "THREADED"                         },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(BIND_SUBOPCODE_THREADED e) {
  CONST_MAP(BIND_SUBOPCODE_THREADED, const char*, 2) enumStrings {
    { BIND_SUBOPCODE_THREADED::BIND_SUBOPCODE_THREADED_APPLY,                            "THREADED_APPLY"                   },
    { BIND_SUBOPCODE_THREADED::BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB, "SET_BIND_ORDINAL_TABLE_SIZE_ULEB" },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(EXPORT_SYMBOL_KINDS e) {
  CONST_MAP(EXPORT_SYMBOL_KINDS, const char*, 3) enumStrings {
    { EXPORT_SYMBOL_KINDS::EXPORT_SYMBOL_FLAGS_KIND_REGULAR,      "REGULAR"      },
    { EXPORT_SYMBOL_KINDS::EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL, "THREAD_LOCAL" },
    { EXPORT_SYMBOL_KINDS::EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE,     "ABSOLUTE"     },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(EXPORT_SYMBOL_FLAGS e) {
  CONST_MAP(EXPORT_SYMBOL_FLAGS, const char*, 3) enumStrings {
    { EXPORT_SYMBOL_FLAGS::EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION,   "WEAK_DEFINITION"   },
    { EXPORT_SYMBOL_FLAGS::EXPORT_SYMBOL_FLAGS_REEXPORT,          "REEXPORT"          },
    { EXPORT_SYMBOL_FLAGS::EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER, "STUB_AND_RESOLVER" },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(VM_PROTECTIONS e) {
  CONST_MAP(VM_PROTECTIONS, const char*, 3) enumStrings {
    { VM_PROTECTIONS::VM_PROT_READ,    "READ"    },
    { VM_PROTECTIONS::VM_PROT_WRITE,   "WRITE"   },
    { VM_PROTECTIONS::VM_PROT_EXECUTE, "EXECUTE" },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(SYMBOL_ORIGINS e) {
  CONST_MAP(SYMBOL_ORIGINS, const char*, 3) enumStrings {
    { SYMBOL_ORIGINS::SYM_ORIGIN_UNKNOWN,     "UNKNOWN"     },
    { SYMBOL_ORIGINS::SYM_ORIGIN_DYLD_EXPORT, "DYLD_EXPORT" },
    { SYMBOL_ORIGINS::SYM_ORIGIN_LC_SYMTAB,   "LC_SYMTAB"   },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(DataCodeEntry::TYPES e) {
  CONST_MAP(DataCodeEntry::TYPES, const char*, 6) enumStrings {
    { DataCodeEntry::TYPES::UNKNOWN,           "UNKNOWN"           },
    { DataCodeEntry::TYPES::DATA,              "DATA"              },
    { DataCodeEntry::TYPES::JUMP_TABLE_8,      "JUMP_TABLE_8"      },
    { DataCodeEntry::TYPES::JUMP_TABLE_16,     "JUMP_TABLE_16"     },
    { DataCodeEntry::TYPES::JUMP_TABLE_32,     "JUMP_TABLE_32"     },
    { DataCodeEntry::TYPES::ABS_JUMP_TABLE_32, "ABS_JUMP_TABLE_32" },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNKNOWN" : it->second;
}

const char* to_string(BuildVersion::PLATFORMS e) {
  CONST_MAP(BuildVersion::PLATFORMS, const char*, 5) enumStrings {
    { BuildVersion::PLATFORMS::UNKNOWN,   "UNKNOWN"   },
    { BuildVersion::PLATFORMS::MACOS,     "MACOS"     },
    { BuildVersion::PLATFORMS::IOS,       "IOS"       },
    { BuildVersion::PLATFORMS::TVOS,      "TVOS"      },
    { BuildVersion::PLATFORMS::WATCHOS,   "WATCHOS"   },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNKNOWN" : it->second;
}


const char* to_string(BuildToolVersion::TOOLS e) {
  CONST_MAP(BuildToolVersion::TOOLS, const char*, 4) enumStrings {
    { BuildToolVersion::TOOLS::UNKNOWN, "UNKNOWN"   },
    { BuildToolVersion::TOOLS::SWIFT,   "SWIFT"     },
    { BuildToolVersion::TOOLS::CLANG,   "CLANG"     },
    { BuildToolVersion::TOOLS::LD,      "LD"        },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNKNOWN" : it->second;
}

const char* to_string(DYLD_CHAINED_PTR_FORMAT e) {
  CONST_MAP(DYLD_CHAINED_PTR_FORMAT, const char*, 12) enumStrings {
    { DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E,              "PTR_ARM64E"              },
    { DYLD_CHAINED_PTR_FORMAT::PTR_64,                  "PTR_64"                  },
    { DYLD_CHAINED_PTR_FORMAT::PTR_32,                  "PTR_32"                  },
    { DYLD_CHAINED_PTR_FORMAT::PTR_32_CACHE,            "PTR_32_CACHE"            },
    { DYLD_CHAINED_PTR_FORMAT::PTR_32_FIRMWARE,         "PTR_32_FIRMWARE"         },
    { DYLD_CHAINED_PTR_FORMAT::PTR_64_OFFSET,           "PTR_64_OFFSET"           },
    { DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_KERNEL,       "PTR_ARM64E_KERNEL"       },
    { DYLD_CHAINED_PTR_FORMAT::PTR_64_KERNEL_CACHE,     "PTR_64_KERNEL_CACHE"     },
    { DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_USERLAND,     "PTR_ARM64E_USERLAND"     },
    { DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_FIRMWARE,     "PTR_ARM64E_FIRMWARE"     },
    { DYLD_CHAINED_PTR_FORMAT::PTR_X86_64_KERNEL_CACHE, "PTR_X86_64_KERNEL_CACHE" },
    { DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_USERLAND24,   "PTR_ARM64E_USERLAND24"   },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNKNOWN" : it->second;
}

const char* to_string(DYLD_CHAINED_FORMAT e) {
  CONST_MAP(DYLD_CHAINED_FORMAT, const char*, 3) enumStrings {
    { DYLD_CHAINED_FORMAT::IMPORT,          "IMPORT"          },
    { DYLD_CHAINED_FORMAT::IMPORT_ADDEND,   "IMPORT_ADDEND"   },
    { DYLD_CHAINED_FORMAT::IMPORT_ADDEND64, "IMPORT_ADDEND64" },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNKNOWN" : it->second;
}

}
}
