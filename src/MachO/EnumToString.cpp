/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#include "LIEF/MachO/Structures.hpp"
#include "LIEF/MachO/EnumToString.hpp"
#include <map>

namespace LIEF {
namespace MachO {


const char* to_string(MACHO_TYPES e) {
  const std::map<MACHO_TYPES, const char*> enumStrings {
      { MACHO_TYPES::MH_MAGIC,    "MAGIC"},
      { MACHO_TYPES::MH_CIGAM,    "CIGAM"},
      { MACHO_TYPES::MH_MAGIC_64, "MAGIC_64"},
      { MACHO_TYPES::MH_CIGAM_64, "CIGAM_64"},
      { MACHO_TYPES::FAT_MAGIC,   "FAT_MAGIC"},
      { MACHO_TYPES::FAT_CIGAM,   "FAT_CIGAM"}
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(FILE_TYPES e) {
  const std::map<FILE_TYPES, const char*> enumStrings {
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
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(LOAD_COMMAND_TYPES e) {
  const std::map<LOAD_COMMAND_TYPES, const char*> enumStrings {
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
      { LOAD_COMMAND_TYPES::LC_VERSION_MIN_WATCHOS,      "VERSION_MIN_WATCHOS"}
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(CPU_TYPES e) {
  const std::map<CPU_TYPES, const char*> enumStrings {
      { CPU_TYPES::CPU_TYPE_ANY,       "ANY"},
      { CPU_TYPES::CPU_TYPE_X86,       "x86"},
      { CPU_TYPES::CPU_TYPE_I386,      "i386"},
      { CPU_TYPES::CPU_TYPE_X86_64,    "x86_64"},
      //{ CPU_TYPES::CPU_TYPE_MIPS,      "MIPS"},
      { CPU_TYPES::CPU_TYPE_MC98000,   "MC98000"},
      { CPU_TYPES::CPU_TYPE_ARM,       "ARM"},
      { CPU_TYPES::CPU_TYPE_ARM64,     "ARM64"},
      { CPU_TYPES::CPU_TYPE_SPARC,     "SPARC"},
      { CPU_TYPES::CPU_TYPE_POWERPC,   "POWERPC"},
      { CPU_TYPES::CPU_TYPE_POWERPC64, "POWERPC64"}
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(HEADER_FLAGS e) {
  const std::map<HEADER_FLAGS, const char*> enumStrings {
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
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(SECTION_TYPES e) {
  const std::map<SECTION_TYPES, const char*> enumStrings {
      { SECTION_TYPES::S_REGULAR,                             "REGULAR"},
      { SECTION_TYPES::S_ZEROFILL,                            "ZEROFILL"},
      { SECTION_TYPES::S_CSTRING_LITERALS,                    "CSTRING_LITERALS"},
      { SECTION_TYPES::S_4BYTE_LITERALS,                      "S_4BYTE_LITERALS"},
      { SECTION_TYPES::S_8BYTE_LITERALS,                      "S_8BYTE_LITERALS"},
      { SECTION_TYPES::S_LITERAL_POINTERS,                    "LITERAL_POINTERS"},
      { SECTION_TYPES::S_NON_LAZY_SYMBOL_POINTERS,            "NON_LAZY_SYMBOL_POINTERS"},
      { SECTION_TYPES::S_LAZY_SYMBOL_POINTERS,                "LAZY_SYMBOL_POINTERS"},
      { SECTION_TYPES::S_SYMBOL_STUBS,                        "SYMBOL_STUBS"},
      { SECTION_TYPES::S_MOD_INIT_FUNC_POINTERS,              "MOD_INIT_FUNC_POINTERS"},
      { SECTION_TYPES::S_MOD_TERM_FUNC_POINTERS,              "MOD_TERM_FUNC_POINTERS"},
      { SECTION_TYPES::S_COALESCED,                           "COALESCED"},
      { SECTION_TYPES::S_GB_ZEROFILL,                         "GB_ZEROFILL"},
      { SECTION_TYPES::S_INTERPOSING,                         "INTERPOSING"},
      { SECTION_TYPES::S_16BYTE_LITERALS,                     "S_16BYTE_LITERALS"},
      { SECTION_TYPES::S_DTRACE_DOF,                          "DTRACE_DOF"},
      { SECTION_TYPES::S_LAZY_DYLIB_SYMBOL_POINTERS,          "LAZY_DYLIB_SYMBOL_POINTERS"},
      { SECTION_TYPES::S_THREAD_LOCAL_REGULAR,                "THREAD_LOCAL_REGULAR"},
      { SECTION_TYPES::S_THREAD_LOCAL_ZEROFILL,               "THREAD_LOCAL_ZEROFILL"},
      { SECTION_TYPES::S_THREAD_LOCAL_VARIABLES,              "THREAD_LOCAL_VARIABLES"},
      { SECTION_TYPES::S_THREAD_LOCAL_VARIABLE_POINTERS,      "THREAD_LOCAL_VARIABLE_POINTERS"},
      { SECTION_TYPES::S_THREAD_LOCAL_INIT_FUNCTION_POINTERS, "THREAD_LOCAL_INIT_FUNCTION_POINTERS"}
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(SECTION_FLAGS e) {
  const std::map<SECTION_FLAGS, const char*> enumStrings {
    { SECTION_FLAGS::S_ATTR_PURE_INSTRUCTIONS,   "PURE_INSTRUCTIONS"},
    { SECTION_FLAGS::S_ATTR_NO_TOC,              "NO_TOC"},
    { SECTION_FLAGS::S_ATTR_STRIP_STATIC_SYMS,   "STRIP_STATIC_SYMS"},
    { SECTION_FLAGS::S_ATTR_NO_DEAD_STRIP,       "NO_DEAD_STRIP"},
    { SECTION_FLAGS::S_ATTR_LIVE_SUPPORT,        "LIVE_SUPPORT"},
    { SECTION_FLAGS::S_ATTR_SELF_MODIFYING_CODE, "SELF_MODIFYING_CODE"},
    { SECTION_FLAGS::S_ATTR_DEBUG,               "DEBUG"},
    { SECTION_FLAGS::S_ATTR_SOME_INSTRUCTIONS,   "SOME_INSTRUCTIONS"},
    { SECTION_FLAGS::S_ATTR_EXT_RELOC,           "EXT_RELOC"},
    { SECTION_FLAGS::S_ATTR_LOC_RELOC,           "LOC_RELOC"}
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(SYMBOL_TYPES e) {
  const std::map<SYMBOL_TYPES, const char*> enumStrings {
    { SYMBOL_TYPES::N_STAB, "STAB"},
    { SYMBOL_TYPES::N_PEXT, "PEXT"},
    { SYMBOL_TYPES::N_TYPE, "TYPE"},
    { SYMBOL_TYPES::N_EXT,  "EXT"}
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(N_LIST_TYPES e) {
  const std::map<N_LIST_TYPES, const char*> enumStrings {
    { N_LIST_TYPES::N_UNDF, "UNDF"},
    { N_LIST_TYPES::N_ABS,  "ABS"},
    { N_LIST_TYPES::N_SECT, "SECT"},
    { N_LIST_TYPES::N_PBUD, "PBUD"},
    { N_LIST_TYPES::N_INDR, "INDR"}
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(SYMBOL_DESCRIPTIONS e) {
  const std::map<SYMBOL_DESCRIPTIONS, const char*> enumStrings {
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
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(X86_RELOCATION e) {
  const std::map<X86_RELOCATION, const char*> enumStrings {
    { X86_RELOCATION::GENERIC_RELOC_VANILLA,        "VANILLA"        },
    { X86_RELOCATION::GENERIC_RELOC_PAIR,           "PAIR"           },
    { X86_RELOCATION::GENERIC_RELOC_SECTDIFF,       "SECTDIFF"       },
    { X86_RELOCATION::GENERIC_RELOC_PB_LA_PTR,      "PB_LA_PTR"      },
    { X86_RELOCATION::GENERIC_RELOC_LOCAL_SECTDIFF, "LOCAL_SECTDIFF" },
    { X86_RELOCATION::GENERIC_RELOC_TLV,            "TLV"            },
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(X86_64_RELOCATION e) {
  const std::map<X86_64_RELOCATION, const char*> enumStrings {
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
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(PPC_RELOCATION e) {
  const std::map<PPC_RELOCATION, const char*> enumStrings {
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
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(ARM_RELOCATION e) {
  const std::map<ARM_RELOCATION, const char*> enumStrings {
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
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(ARM64_RELOCATION e) {
  const std::map<ARM64_RELOCATION, const char*> enumStrings {
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
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(RELOCATION_ORIGINS e) {
  const std::map<RELOCATION_ORIGINS, const char*> enumStrings {
    { RELOCATION_ORIGINS::ORIGIN_UNKNOWN,     "UNKNOWN"     },
    { RELOCATION_ORIGINS::ORIGIN_DYLDINFO,    "DYLDINFO"    },
    { RELOCATION_ORIGINS::ORIGIN_RELOC_TABLE, "RELOC_TABLE" },
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(REBASE_TYPES e) {
  const std::map<REBASE_TYPES, const char*> enumStrings {
    { REBASE_TYPES::REBASE_TYPE_POINTER,          "POINTER"         },
    { REBASE_TYPES::REBASE_TYPE_TEXT_ABSOLUTE32,  "TEXT_ABSOLUTE32" },
    { REBASE_TYPES::REBASE_TYPE_TEXT_PCREL32,     "TEXT_PCREL32"    },
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(BINDING_CLASS e) {
  const std::map<BINDING_CLASS, const char*> enumStrings {
    { BINDING_CLASS::BIND_CLASS_WEAK,     "WEAK"      },
    { BINDING_CLASS::BIND_CLASS_LAZY,     "LAZY"      },
    { BINDING_CLASS::BIND_CLASS_STANDARD, "STANDARD"  },
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(REBASE_OPCODES e) {
  const std::map<REBASE_OPCODES, const char*> enumStrings {
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
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(BIND_TYPES e) {
  const std::map<BIND_TYPES, const char*> enumStrings {
    { BIND_TYPES::BIND_TYPE_POINTER,         "POINTER"         },
    { BIND_TYPES::BIND_TYPE_TEXT_ABSOLUTE32, "TEXT_ABSOLUTE32" },
    { BIND_TYPES::BIND_TYPE_TEXT_PCREL32,    "TEXT_PCREL32"    },
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(BIND_SPECIAL_DYLIB e) {
  const std::map<BIND_SPECIAL_DYLIB, const char*> enumStrings {
    { BIND_SPECIAL_DYLIB::BIND_SPECIAL_DYLIB_SELF,            "SELF"            },
    { BIND_SPECIAL_DYLIB::BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE, "MAIN_EXECUTABLE" },
    { BIND_SPECIAL_DYLIB::BIND_SPECIAL_DYLIB_FLAT_LOOKUP,     "FLAT_LOOKUP"     },
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(BIND_OPCODES e) {
  const std::map<BIND_OPCODES, const char*> enumStrings {
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
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(EXPORT_SYMBOL_KINDS e) {
  const std::map<EXPORT_SYMBOL_KINDS, const char*> enumStrings {
    { EXPORT_SYMBOL_KINDS::EXPORT_SYMBOL_FLAGS_KIND_REGULAR,      "REGULAR"      },
    { EXPORT_SYMBOL_KINDS::EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL, "THREAD_LOCAL" },
    { EXPORT_SYMBOL_KINDS::EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE,     "ABSOLUTE"     },
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(VM_PROTECTIONS e) {
  const std::map<VM_PROTECTIONS, const char*> enumStrings {
    { VM_PROTECTIONS::VM_PROT_READ,    "READ"    },
    { VM_PROTECTIONS::VM_PROT_WRITE,   "WRITE"   },
    { VM_PROTECTIONS::VM_PROT_EXECUTE, "EXECUTE" },
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}



}
}
