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
#include "LIEF/ELF/Structures.hpp"
#include "LIEF/ELF/EnumToString.hpp"
#include <map>

namespace LIEF {
namespace ELF {

const char* to_string(SYMBOL_BINDINGS e) {
  const std::map<SYMBOL_BINDINGS, const char*> enumStrings {
    { SYMBOL_BINDINGS::STB_LOCAL,      "LOCAL" },
    { SYMBOL_BINDINGS::STB_GLOBAL,     "GLOBAL" },
    { SYMBOL_BINDINGS::STB_WEAK,       "WEAK" },
    { SYMBOL_BINDINGS::STB_GNU_UNIQUE, "GNU_UNIQUE" },
    { SYMBOL_BINDINGS::STB_LOOS,       "LOOS" },
    { SYMBOL_BINDINGS::STB_HIOS,       "HIOS" },
    { SYMBOL_BINDINGS::STB_LOPROC,     "LOPROC" },
    { SYMBOL_BINDINGS::STB_HIPROC,     "HIPROC" }
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(E_TYPE e) {
  const std::map<E_TYPE, const char*> enumStrings {
    { E_TYPE::ET_NONE,   "NONE" },
    { E_TYPE::ET_REL,    "RELOCATABLE" },
    { E_TYPE::ET_EXEC,   "EXECUTABLE" },
    { E_TYPE::ET_DYN,    "DYNAMIC" },
    { E_TYPE::ET_CORE,   "CORE" },
    { E_TYPE::ET_LOPROC, "LOPROC" },
    { E_TYPE::ET_HIPROC, "HIPROC" }
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(VERSION e) {
  const std::map<VERSION, const char*> enumStrings {
    { VERSION::EV_NONE,    "NONE" },
    { VERSION::EV_CURRENT, "CURRENT" }
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(ARCH e) {
  const std::map<ARCH, const char*> enumStrings {
    { ARCH::EM_NONE,          "None" },
    { ARCH::EM_M32,           "M32"},
    { ARCH::EM_SPARC,         "SPARC"},
    { ARCH::EM_386,           "i386"},
    { ARCH::EM_68K,           "68K"},
    { ARCH::EM_88K,           "88K"},
    { ARCH::EM_IAMCU,         "IAMCU"},
    { ARCH::EM_860,           "860"},
    { ARCH::EM_MIPS,          "MIPS"},
    { ARCH::EM_S370,          "S370"},
    { ARCH::EM_MIPS_RS3_LE,   "MIPS_RS3_LE"},
    { ARCH::EM_PARISC,        "PARISC"},
    { ARCH::EM_VPP500,        "VPP500"},
    { ARCH::EM_SPARC32PLUS,   "SPARC32PLUS"},
    { ARCH::EM_960,           "960"},
    { ARCH::EM_PPC,           "PPC"},
    { ARCH::EM_PPC64,         "PPC64"},
    { ARCH::EM_S390,          "S390"},
    { ARCH::EM_SPU,           "SPU"},
    { ARCH::EM_V800,          "V800"},
    { ARCH::EM_FR20,          "FR20"},
    { ARCH::EM_RH32,          "RH32"},
    { ARCH::EM_RCE,           "RCE"},
    { ARCH::EM_ARM,           "ARM"},
    { ARCH::EM_ALPHA,         "ALPHA"},
    { ARCH::EM_SH,            "SH"},
    { ARCH::EM_SPARCV9,       "SPARCV9"},
    { ARCH::EM_TRICORE,       "TRICORE"},
    { ARCH::EM_ARC,           "ARC"},
    { ARCH::EM_H8_300,        "H8_300"},
    { ARCH::EM_H8_300H,       "H8_300H"},
    { ARCH::EM_H8S,           "H8S"},
    { ARCH::EM_H8_500,        "H8_500"},
    { ARCH::EM_IA_64,         "IA_64"},
    { ARCH::EM_MIPS_X,        "MIPS_X"},
    { ARCH::EM_COLDFIRE,      "COLDFIRE"},
    { ARCH::EM_68HC12,        "68HC12"},
    { ARCH::EM_MMA,           "MMA"},
    { ARCH::EM_PCP,           "PCP"},
    { ARCH::EM_NCPU,          "NCPU"},
    { ARCH::EM_NDR1,          "NDR1"},
    { ARCH::EM_STARCORE,      "STARCORE"},
    { ARCH::EM_ME16,          "ME16"},
    { ARCH::EM_ST100,         "ST100"},
    { ARCH::EM_TINYJ,         "TINYJ"},
    { ARCH::EM_X86_64,        "x86_64"},
    { ARCH::EM_PDSP,          "PDSP"},
    { ARCH::EM_PDP10,         "PDP10"},
    { ARCH::EM_PDP11,         "PDP11"},
    { ARCH::EM_FX66,          "FX66"},
    { ARCH::EM_ST9PLUS,       "ST9PLUS"},
    { ARCH::EM_ST7,           "ST7"},
    { ARCH::EM_68HC16,        "68HC16"},
    { ARCH::EM_68HC11,        "68HC11"},
    { ARCH::EM_68HC08,        "68HC08"},
    { ARCH::EM_68HC05,        "68HC05"},
    { ARCH::EM_SVX,           "SVX"},
    { ARCH::EM_ST19,          "ST19"},
    { ARCH::EM_VAX,           "VAX"},
    { ARCH::EM_CRIS,          "CRIS"},
    { ARCH::EM_JAVELIN,       "JAVELIN"},
    { ARCH::EM_FIREPATH,      "FIREPATH"},
    { ARCH::EM_ZSP,           "ZSP"},
    { ARCH::EM_MMIX,          "MMIX"},
    { ARCH::EM_HUANY,         "HUANY"},
    { ARCH::EM_PRISM,         "PRISM"},
    { ARCH::EM_AVR,           "AVR"},
    { ARCH::EM_FR30,          "FR30"},
    { ARCH::EM_D10V,          "D10V"},
    { ARCH::EM_D30V,          "D30V"},
    { ARCH::EM_V850,          "V850"},
    { ARCH::EM_M32R,          "M32R"},
    { ARCH::EM_MN10300,       "MN10300"},
    { ARCH::EM_MN10200,       "MN10200"},
    { ARCH::EM_PJ,            "PJ"},
    { ARCH::EM_OPENRISC,      "OPENRISC"},
    { ARCH::EM_ARC_COMPACT,   "ARC_COMPACT"},
    { ARCH::EM_XTENSA,        "XTENSA"},
    { ARCH::EM_VIDEOCORE,     "VIDEOCORE"},
    { ARCH::EM_TMM_GPP,       "TMM_GPP"},
    { ARCH::EM_NS32K,         "NS32K"},
    { ARCH::EM_TPC,           "TPC"},
    { ARCH::EM_SNP1K,         "SNP1K"},
    { ARCH::EM_ST200,         "ST200"},
    { ARCH::EM_IP2K,          "IP2K"},
    { ARCH::EM_MAX,           "MAX"},
    { ARCH::EM_CR,            "CR"},
    { ARCH::EM_F2MC16,        "F2MC16"},
    { ARCH::EM_MSP430,        "MSP430"},
    { ARCH::EM_BLACKFIN,      "BLACKFIN"},
    { ARCH::EM_SE_C33,        "SE_C33"},
    { ARCH::EM_SEP,           "SEP"},
    { ARCH::EM_ARCA,          "ARCA"},
    { ARCH::EM_UNICORE,       "UNICORE"},
    { ARCH::EM_EXCESS,        "EXCESS"},
    { ARCH::EM_DXP,           "DXP"},
    { ARCH::EM_ALTERA_NIOS2,  "ALTERA_NIOS2"},
    { ARCH::EM_CRX,           "CRX"},
    { ARCH::EM_XGATE,         "XGATE"},
    { ARCH::EM_C166,          "C166"},
    { ARCH::EM_M16C,          "M16C"},
    { ARCH::EM_DSPIC30F,      "DSPIC30F"},
    { ARCH::EM_CE,            "CE"},
    { ARCH::EM_M32C,          "M32C"},
    { ARCH::EM_TSK3000,       "TSK3000"},
    { ARCH::EM_RS08,          "RS08"},
    { ARCH::EM_SHARC,         "SHARC"},
    { ARCH::EM_ECOG2,         "ECOG2"},
    { ARCH::EM_SCORE7,        "SCORE7"},
    { ARCH::EM_DSP24,         "DSP24"},
    { ARCH::EM_VIDEOCORE3,    "VIDEOCORE3"},
    { ARCH::EM_LATTICEMICO32, "LATTICEMICO32"},
    { ARCH::EM_SE_C17,        "SE_C17"},
    { ARCH::EM_TI_C6000,      "TI_C6000"},
    { ARCH::EM_TI_C2000,      "TI_C2000"},
    { ARCH::EM_TI_C5500,      "TI_C5500"},
    { ARCH::EM_MMDSP_PLUS,    "MMDSP_PLUS"},
    { ARCH::EM_CYPRESS_M8C,   "CYPRESS_M8C"},
    { ARCH::EM_R32C,          "R32C"},
    { ARCH::EM_TRIMEDIA,      "TRIMEDIA"},
    { ARCH::EM_HEXAGON,       "HEXAGON"},
    { ARCH::EM_8051,          "8051"},
    { ARCH::EM_STXP7X,        "STXP7X"},
    { ARCH::EM_NDS32,         "NDS32"},
    { ARCH::EM_ECOG1,         "ECOG1"},
    { ARCH::EM_ECOG1X,        "ECOG1X"},
    { ARCH::EM_MAXQ30,        "MAXQ30"},
    { ARCH::EM_XIMO16,        "XIMO16"},
    { ARCH::EM_MANIK,         "MANIK"},
    { ARCH::EM_CRAYNV2,       "CRAYNV2"},
    { ARCH::EM_RX,            "RX"},
    { ARCH::EM_METAG,         "METAG"},
    { ARCH::EM_MCST_ELBRUS,   "MCST_ELBRUS"},
    { ARCH::EM_ECOG16,        "ECOG16"},
    { ARCH::EM_CR16,          "CR16"},
    { ARCH::EM_ETPU,          "ETPU"},
    { ARCH::EM_SLE9X,         "SLE9X"},
    { ARCH::EM_L10M,          "L10M"},
    { ARCH::EM_K10M,          "K10M"},
    { ARCH::EM_AARCH64,       "AARCH64"},
    { ARCH::EM_AVR32,         "AVR32"},
    { ARCH::EM_STM8,          "STM8"},
    { ARCH::EM_TILE64,        "TILE64"},
    { ARCH::EM_TILEPRO,       "TILEPRO"},
    { ARCH::EM_CUDA,          "CUDA"},
    { ARCH::EM_TILEGX,        "TILEGX"},
    { ARCH::EM_CLOUDSHIELD,   "CLOUDSHIELD"},
    { ARCH::EM_COREA_1ST,     "COREA_1ST"},
    { ARCH::EM_COREA_2ND,     "COREA_2ND"},
    { ARCH::EM_ARC_COMPACT2,   "ARC_COMPACT2"},
    { ARCH::EM_OPEN8,         "OPEN8"},
    { ARCH::EM_RL78,          "RL78"},
    { ARCH::EM_VIDEOCORE5,    "VIDEOCORE5"},
    { ARCH::EM_78KOR,         "78KOR"},
    { ARCH::EM_56800EX,       "56800EX"},
    { ARCH::EM_BA1,           "BA1"},
    { ARCH::EM_BA2,           "BA2"},
    { ARCH::EM_XCORE,         "XCORE"},
    { ARCH::EM_MCHP_PIC,      "MCHP_PIC"},
    { ARCH::EM_INTEL205,      "INTEL205"},
    { ARCH::EM_INTEL206,      "INTEL206"},
    { ARCH::EM_INTEL207,      "INTEL207"},
    { ARCH::EM_INTEL208,      "INTEL208"},
    { ARCH::EM_INTEL209,      "INTEL209"},
    { ARCH::EM_KM32,          "KM32"},
    { ARCH::EM_KMX32,         "KMX32"},
    { ARCH::EM_KMX16,         "KMX16"},
    { ARCH::EM_KMX8,          "KMX8"},
    { ARCH::EM_KVARC,         "KVARC"},
    { ARCH::EM_CDP,           "CDP"},
    { ARCH::EM_COGE,          "COGE"},
    { ARCH::EM_COOL,          "COOL"},
    { ARCH::EM_NORC,          "NORC"},
    { ARCH::EM_CSR_KALIMBA,   "CSR_KALIMBA"},
    { ARCH::EM_AMDGPU,        "AMDGPU"}
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(SEGMENT_TYPES e) {
  const std::map<SEGMENT_TYPES, const char*> enumStrings {
    { SEGMENT_TYPES::PT_LOAD,          "LOAD" },
    { SEGMENT_TYPES::PT_DYNAMIC,       "DYNAMIC" },
    { SEGMENT_TYPES::PT_INTERP,        "INTERP" },
    { SEGMENT_TYPES::PT_NOTE,          "NOTE" },
    { SEGMENT_TYPES::PT_SHLIB,         "SHLIB" },
    { SEGMENT_TYPES::PT_PHDR,          "PHDR" },
    { SEGMENT_TYPES::PT_TLS,           "TLS" },
    { SEGMENT_TYPES::PT_LOOS,          "LOOS" },
    { SEGMENT_TYPES::PT_HIOS,          "HIOS" },
    { SEGMENT_TYPES::PT_LOPROC,        "LOPROC" },
    { SEGMENT_TYPES::PT_HIPROC,        "HIPROC" },
    { SEGMENT_TYPES::PT_GNU_EH_FRAME,  "GNU_EH_FRAME" },
    { SEGMENT_TYPES::PT_SUNW_EH_FRAME, "SUNW_EH_FRAME" },
    { SEGMENT_TYPES::PT_SUNW_UNWIND,   "SUNW_UNWIND" },
    { SEGMENT_TYPES::PT_GNU_STACK,     "GNU_STACK" },
    { SEGMENT_TYPES::PT_GNU_RELRO,     "GNU_RELRO" },
    { SEGMENT_TYPES::PT_ARM_ARCHEXT,   "ARM_ARCHEXT" },
    { SEGMENT_TYPES::PT_ARM_EXIDX,     "ARM_EXIDX" },
    { SEGMENT_TYPES::PT_ARM_UNWIND,    "ARM_UNWIND" },
    { SEGMENT_TYPES::PT_MIPS_REGINFO,  "MIPS_REGINFO" },
    { SEGMENT_TYPES::PT_MIPS_RTPROC,   "MIPS_RTPROC" },
    { SEGMENT_TYPES::PT_MIPS_OPTIONS,  "MIPS_OPTIONS" },
    { SEGMENT_TYPES::PT_MIPS_ABIFLAGS, "MIPS_ABIFLAGS" }
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(DYNAMIC_TAGS e) {
  const std::map<DYNAMIC_TAGS, const char*> enumStrings {
    { DYNAMIC_TAGS::DT_NULL,                       "NULL"},
    { DYNAMIC_TAGS::DT_NEEDED,                     "NEEDED"},
    { DYNAMIC_TAGS::DT_PLTRELSZ,                   "PLTRELSZ"},
    { DYNAMIC_TAGS::DT_PLTGOT,                     "PLTGOT"},
    { DYNAMIC_TAGS::DT_HASH,                       "HASH"},
    { DYNAMIC_TAGS::DT_STRTAB,                     "STRTAB"},
    { DYNAMIC_TAGS::DT_SYMTAB,                     "SYMTAB"},
    { DYNAMIC_TAGS::DT_RELA,                       "RELA"},
    { DYNAMIC_TAGS::DT_RELASZ,                     "RELASZ"},
    { DYNAMIC_TAGS::DT_RELAENT,                    "RELAENT"},
    { DYNAMIC_TAGS::DT_STRSZ,                      "STRSZ"},
    { DYNAMIC_TAGS::DT_SYMENT,                     "SYMENT"},
    { DYNAMIC_TAGS::DT_INIT,                       "INIT"},
    { DYNAMIC_TAGS::DT_FINI,                       "FINI"},
    { DYNAMIC_TAGS::DT_SONAME,                     "SONAME"},
    { DYNAMIC_TAGS::DT_RPATH,                      "RPATH"},
    { DYNAMIC_TAGS::DT_SYMBOLIC,                   "SYMBOLIC"},
    { DYNAMIC_TAGS::DT_REL,                        "REL"},
    { DYNAMIC_TAGS::DT_RELSZ,                      "RELSZ"},
    { DYNAMIC_TAGS::DT_RELENT,                     "RELENT"},
    { DYNAMIC_TAGS::DT_PLTREL,                     "PLTREL"},
    { DYNAMIC_TAGS::DT_DEBUG,                      "DEBUG"},
    { DYNAMIC_TAGS::DT_TEXTREL,                    "TEXTREL"},
    { DYNAMIC_TAGS::DT_JMPREL,                     "JMPREL"},
    { DYNAMIC_TAGS::DT_BIND_NOW,                   "BIND_NOW"},
    { DYNAMIC_TAGS::DT_INIT_ARRAY,                 "INIT_ARRAY"},
    { DYNAMIC_TAGS::DT_FINI_ARRAY,                 "FINI_ARRAY"},
    { DYNAMIC_TAGS::DT_INIT_ARRAYSZ,               "INIT_ARRAYSZ"},
    { DYNAMIC_TAGS::DT_FINI_ARRAYSZ,               "FINI_ARRAYSZ"},
    { DYNAMIC_TAGS::DT_RUNPATH,                    "RUNPATH"},
    { DYNAMIC_TAGS::DT_FLAGS,                      "FLAGS"},
    { DYNAMIC_TAGS::DT_ENCODING,                   "ENCODING"},
    { DYNAMIC_TAGS::DT_PREINIT_ARRAY,              "PREINIT_ARRAY"},
    { DYNAMIC_TAGS::DT_PREINIT_ARRAYSZ,            "PREINIT_ARRAYSZ"},
    { DYNAMIC_TAGS::DT_LOOS,                       "LOOS"},
    { DYNAMIC_TAGS::DT_HIOS,                       "HIOS"},
    { DYNAMIC_TAGS::DT_LOPROC,                     "LOPROC"},
    { DYNAMIC_TAGS::DT_HIPROC,                     "HIPROC"},
    { DYNAMIC_TAGS::DT_GNU_HASH,                   "GNU_HASH"},
    { DYNAMIC_TAGS::DT_RELACOUNT,                  "RELACOUNT"},
    { DYNAMIC_TAGS::DT_RELCOUNT,                   "RELCOUNT"},
    { DYNAMIC_TAGS::DT_FLAGS_1,                    "FLAGS_1"},
    { DYNAMIC_TAGS::DT_VERSYM,                     "VERSYM"},
    { DYNAMIC_TAGS::DT_VERDEF,                     "VERDEF"},
    { DYNAMIC_TAGS::DT_VERDEFNUM,                  "VERDEFNUM"},
    { DYNAMIC_TAGS::DT_VERNEED,                    "VERNEED"},
    { DYNAMIC_TAGS::DT_VERNEEDNUM,                 "VERNEEDNUM"},
    { DYNAMIC_TAGS::DT_MIPS_RLD_VERSION,           "MIPS_RLD_VERSION"},
    { DYNAMIC_TAGS::DT_MIPS_TIME_STAMP,            "MIPS_TIME_STAMP"},
    { DYNAMIC_TAGS::DT_MIPS_ICHECKSUM,             "MIPS_ICHECKSUM"},
    { DYNAMIC_TAGS::DT_MIPS_IVERSION,              "MIPS_IVERSION"},
    { DYNAMIC_TAGS::DT_MIPS_FLAGS,                 "MIPS_FLAGS"},
    { DYNAMIC_TAGS::DT_MIPS_BASE_ADDRESS,          "MIPS_BASE_ADDRESS"},
    { DYNAMIC_TAGS::DT_MIPS_MSYM,                  "MIPS_MSYM"},
    { DYNAMIC_TAGS::DT_MIPS_CONFLICT,              "MIPS_CONFLICT"},
    { DYNAMIC_TAGS::DT_MIPS_LIBLIST,               "MIPS_LIBLIST"},
    { DYNAMIC_TAGS::DT_MIPS_LOCAL_GOTNO,           "MIPS_LOCAL_GOTNO"},
    { DYNAMIC_TAGS::DT_MIPS_CONFLICTNO,            "MIPS_CONFLICTNO"},
    { DYNAMIC_TAGS::DT_MIPS_LIBLISTNO,             "MIPS_LIBLISTNO"},
    { DYNAMIC_TAGS::DT_MIPS_SYMTABNO,              "MIPS_SYMTABNO"},
    { DYNAMIC_TAGS::DT_MIPS_UNREFEXTNO,            "MIPS_UNREFEXTNO"},
    { DYNAMIC_TAGS::DT_MIPS_GOTSYM,                "MIPS_GOTSYM"},
    { DYNAMIC_TAGS::DT_MIPS_HIPAGENO,              "MIPS_HIPAGENO"},
    { DYNAMIC_TAGS::DT_MIPS_RLD_MAP,               "MIPS_RLD_MAP"},
    { DYNAMIC_TAGS::DT_MIPS_DELTA_CLASS,           "MIPS_DELTA_CLASS"},
    { DYNAMIC_TAGS::DT_MIPS_DELTA_CLASS_NO,        "MIPS_DELTA_CLASS_NO"},
    { DYNAMIC_TAGS::DT_MIPS_DELTA_INSTANCE,        "MIPS_DELTA_INSTANCE"},
    { DYNAMIC_TAGS::DT_MIPS_DELTA_INSTANCE_NO,     "MIPS_DELTA_INSTANCE_NO"},
    { DYNAMIC_TAGS::DT_MIPS_DELTA_RELOC,           "MIPS_DELTA_RELOC"},
    { DYNAMIC_TAGS::DT_MIPS_DELTA_RELOC_NO,        "MIPS_DELTA_RELOC_NO"},
    { DYNAMIC_TAGS::DT_MIPS_DELTA_SYM,             "MIPS_DELTA_SYM"},
    { DYNAMIC_TAGS::DT_MIPS_DELTA_SYM_NO,          "MIPS_DELTA_SYM_NO"},
    { DYNAMIC_TAGS::DT_MIPS_DELTA_CLASSSYM,        "MIPS_DELTA_CLASSSYM"},
    { DYNAMIC_TAGS::DT_MIPS_DELTA_CLASSSYM_NO,     "MIPS_DELTA_CLASSSYM_NO"},
    { DYNAMIC_TAGS::DT_MIPS_CXX_FLAGS,             "MIPS_CXX_FLAGS"},
    { DYNAMIC_TAGS::DT_MIPS_PIXIE_INIT,            "MIPS_PIXIE_INIT"},
    { DYNAMIC_TAGS::DT_MIPS_SYMBOL_LIB,            "MIPS_SYMBOL_LIB"},
    { DYNAMIC_TAGS::DT_MIPS_LOCALPAGE_GOTIDX,      "MIPS_LOCALPAGE_GOTIDX"},
    { DYNAMIC_TAGS::DT_MIPS_LOCAL_GOTIDX,          "MIPS_LOCAL_GOTIDX"},
    { DYNAMIC_TAGS::DT_MIPS_HIDDEN_GOTIDX,         "MIPS_HIDDEN_GOTIDX"},
    { DYNAMIC_TAGS::DT_MIPS_PROTECTED_GOTIDX,      "MIPS_PROTECTED_GOTIDX"},
    { DYNAMIC_TAGS::DT_MIPS_OPTIONS,               "MIPS_OPTIONS"},
    { DYNAMIC_TAGS::DT_MIPS_INTERFACE,             "MIPS_INTERFACE"},
    { DYNAMIC_TAGS::DT_MIPS_DYNSTR_ALIGN,          "MIPS_DYNSTR_ALIGN"},
    { DYNAMIC_TAGS::DT_MIPS_INTERFACE_SIZE,        "MIPS_INTERFACE_SIZE"},
    { DYNAMIC_TAGS::DT_MIPS_RLD_TEXT_RESOLVE_ADDR, "MIPS_RLD_TEXT_RESOLVE_ADDR"},
    { DYNAMIC_TAGS::DT_MIPS_PERF_SUFFIX,           "MIPS_PERF_SUFFIX"},
    { DYNAMIC_TAGS::DT_MIPS_COMPACT_SIZE,          "MIPS_COMPACT_SIZE"},
    { DYNAMIC_TAGS::DT_MIPS_GP_VALUE,              "MIPS_GP_VALUE"},
    { DYNAMIC_TAGS::DT_MIPS_AUX_DYNAMIC,           "MIPS_AUX_DYNAMIC"},
    { DYNAMIC_TAGS::DT_MIPS_PLTGOT,                "MIPS_PLTGOT"},
    { DYNAMIC_TAGS::DT_MIPS_RWPLT,                 "MIPS_RWPLT"}
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(SECTION_TYPES e) {
  const std::map<SECTION_TYPES, const char*> enumStrings {
    { SECTION_TYPES::SHT_NULL,               "NULL"},
    { SECTION_TYPES::SHT_PROGBITS,           "PROGBITS"},
    { SECTION_TYPES::SHT_SYMTAB,             "SYMTAB"},
    { SECTION_TYPES::SHT_STRTAB,             "STRTAB"},
    { SECTION_TYPES::SHT_RELA,               "RELA"},
    { SECTION_TYPES::SHT_HASH,               "HASH"},
    { SECTION_TYPES::SHT_DYNAMIC,            "DYNAMIC"},
    { SECTION_TYPES::SHT_NOTE,               "NOTE"},
    { SECTION_TYPES::SHT_NOBITS,             "NOBITS"},
    { SECTION_TYPES::SHT_REL,                "REL"},
    { SECTION_TYPES::SHT_SHLIB,              "SHLIB"},
    { SECTION_TYPES::SHT_DYNSYM,             "DYNSYM"},
    { SECTION_TYPES::SHT_INIT_ARRAY,         "INIT_ARRAY"},
    { SECTION_TYPES::SHT_FINI_ARRAY,         "FINI_ARRAY"},
    { SECTION_TYPES::SHT_PREINIT_ARRAY,      "PREINIT_ARRAY"},
    { SECTION_TYPES::SHT_GROUP,              "GROUP"},
    { SECTION_TYPES::SHT_SYMTAB_SHNDX,       "SYMTAB_SHNDX"},
    { SECTION_TYPES::SHT_LOOS,               "LOOS"},
    { SECTION_TYPES::SHT_GNU_ATTRIBUTES,     "GNU_ATTRIBUTES"},
    { SECTION_TYPES::SHT_GNU_HASH,           "GNU_HASH"},
    { SECTION_TYPES::SHT_GNU_verdef,         "GNU_VERDEF"},
    { SECTION_TYPES::SHT_GNU_verneed,        "GNU_VERNEED"},
    { SECTION_TYPES::SHT_GNU_versym,         "GNU_VERSYM"},
    { SECTION_TYPES::SHT_HIOS,               "HIOS"},
    { SECTION_TYPES::SHT_LOPROC,             "LOPROC"},
    { SECTION_TYPES::SHT_ARM_EXIDX,          "ARM_EXIDX"},
    { SECTION_TYPES::SHT_ARM_PREEMPTMAP,     "ARM_PREEMPTMAP"},
    { SECTION_TYPES::SHT_ARM_ATTRIBUTES,     "ARM_ATTRIBUTES"},
    { SECTION_TYPES::SHT_ARM_DEBUGOVERLAY,   "ARM_DEBUGOVERLAY"},
    { SECTION_TYPES::SHT_ARM_OVERLAYSECTION, "ARM_OVERLAYSECTION"},
    { SECTION_TYPES::SHT_HEX_ORDERED,        "HEX_ORDERED"},
    { SECTION_TYPES::SHT_X86_64_UNWIND,      "X86_64_UNWIND"},
    { SECTION_TYPES::SHT_MIPS_REGINFO,       "MIPS_REGINFO"},
    { SECTION_TYPES::SHT_MIPS_OPTIONS,       "MIPS_OPTIONS"},
    { SECTION_TYPES::SHT_MIPS_ABIFLAGS,      "MIPS_ABIFLAGS"},
    { SECTION_TYPES::SHT_HIPROC,             "HIPROC"},
    { SECTION_TYPES::SHT_LOUSER,             "LOUSER"},
    { SECTION_TYPES::SHT_HIUSER,             "HIUSER"}
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(SECTION_FLAGS e) {
  const std::map<SECTION_FLAGS, const char*> enumStrings {
    { SECTION_FLAGS::SHF_NONE,             "NONE"},
    { SECTION_FLAGS::SHF_WRITE,            "WRITE"},
    { SECTION_FLAGS::SHF_ALLOC,            "ALLOC"},
    { SECTION_FLAGS::SHF_EXECINSTR,        "EXECINSTR"},
    { SECTION_FLAGS::SHF_MERGE,            "MERGE"},
    { SECTION_FLAGS::SHF_STRINGS,          "STRINGS"},
    { SECTION_FLAGS::SHF_INFO_LINK,        "INFO_LINK"},
    { SECTION_FLAGS::SHF_LINK_ORDER,       "LINK_ORDER"},
    { SECTION_FLAGS::SHF_OS_NONCONFORMING, "OS_NONCONFORMING"},
    { SECTION_FLAGS::SHF_GROUP,            "GROUP"},
    { SECTION_FLAGS::SHF_TLS,              "TLS"},
    { SECTION_FLAGS::SHF_EXCLUDE,          "EXCLUDE"},
    { SECTION_FLAGS::XCORE_SHF_CP_SECTION, "XCORE_SHF_CP_SECTION"},
    { SECTION_FLAGS::XCORE_SHF_DP_SECTION, "XCORE_SHF_CP_SECTION"},
    { SECTION_FLAGS::SHF_MASKOS,           "MASKOS"},
    { SECTION_FLAGS::SHF_MASKPROC,         "MASKPROC"},
    { SECTION_FLAGS::SHF_HEX_GPREL,        "HEX_GPREL"},
    { SECTION_FLAGS::SHF_MIPS_NODUPES,     "MIPS_NODUPES"},
    { SECTION_FLAGS::SHF_MIPS_NAMES,       "MIPS_NAMES"},
    { SECTION_FLAGS::SHF_MIPS_LOCAL,       "MIPS_LOCAL"},
    { SECTION_FLAGS::SHF_MIPS_NOSTRIP,     "MIPS_NOSTRIP"},
    { SECTION_FLAGS::SHF_MIPS_GPREL,       "MIPS_GPREL"},
    { SECTION_FLAGS::SHF_MIPS_MERGE,       "MIPS_MERGE"},
    { SECTION_FLAGS::SHF_MIPS_ADDR,        "MIPS_ADDR"},
    { SECTION_FLAGS::SHF_MIPS_STRING,      "MIPS_STRING"}
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(SYMBOL_TYPES e) {
  const std::map<SYMBOL_TYPES, const char*> enumStrings {
    { SYMBOL_TYPES::STT_NOTYPE,    "NOTYPE"},
    { SYMBOL_TYPES::STT_OBJECT,    "OBJECT"},
    { SYMBOL_TYPES::STT_FUNC,      "FUNC"},
    { SYMBOL_TYPES::STT_SECTION,   "SECTION"},
    { SYMBOL_TYPES::STT_FILE,      "FILE"},
    { SYMBOL_TYPES::STT_COMMON,    "COMMON"},
    { SYMBOL_TYPES::STT_TLS,       "TLS"},
    { SYMBOL_TYPES::STT_GNU_IFUNC, "GNU_IFUNC"},
    { SYMBOL_TYPES::STT_LOOS,      "LOOS"},
    { SYMBOL_TYPES::STT_HIOS,      "HIOS"},
    { SYMBOL_TYPES::STT_LOPROC,    "LOPROC"},
    { SYMBOL_TYPES::STT_HIPROC,    "HIPROC"}
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(RELOC_x86_64 e) {
  const std::map<RELOC_x86_64, const char*> enumStrings {
    { RELOC_x86_64::R_X86_64_NONE,            "NONE"},
    { RELOC_x86_64::R_X86_64_64,              "64"},
    { RELOC_x86_64::R_X86_64_PC32,            "PC32"},
    { RELOC_x86_64::R_X86_64_GOT32,           "GOT32"},
    { RELOC_x86_64::R_X86_64_PLT32,           "PLT32"},
    { RELOC_x86_64::R_X86_64_COPY,            "COPY"},
    { RELOC_x86_64::R_X86_64_GLOB_DAT,        "GLOB_DAT"},
    { RELOC_x86_64::R_X86_64_JUMP_SLOT,       "JUMP_SLOT"},
    { RELOC_x86_64::R_X86_64_RELATIVE,        "RELATIVE"},
    { RELOC_x86_64::R_X86_64_GOTPCREL,        "GOTPCREL"},
    { RELOC_x86_64::R_X86_64_32,              "32"},
    { RELOC_x86_64::R_X86_64_32S,             "32S"},
    { RELOC_x86_64::R_X86_64_16,              "16"},
    { RELOC_x86_64::R_X86_64_PC16,            "PC16"},
    { RELOC_x86_64::R_X86_64_8,               "8"},
    { RELOC_x86_64::R_X86_64_PC8,             "PC8"},
    { RELOC_x86_64::R_X86_64_DTPMOD64,        "DTPMOD64"},
    { RELOC_x86_64::R_X86_64_DTPOFF64,        "DTPOFF64"},
    { RELOC_x86_64::R_X86_64_TPOFF64,         "TPOFF64"},
    { RELOC_x86_64::R_X86_64_TLSGD,           "TLSGD"},
    { RELOC_x86_64::R_X86_64_TLSLD,           "TLSLD"},
    { RELOC_x86_64::R_X86_64_DTPOFF32,        "DTPOFF32"},
    { RELOC_x86_64::R_X86_64_GOTTPOFF,        "GOTTPOFF"},
    { RELOC_x86_64::R_X86_64_TPOFF32,         "TPOFF32"},
    { RELOC_x86_64::R_X86_64_PC64,            "PC64"},
    { RELOC_x86_64::R_X86_64_GOTOFF64,        "GOTOFF64"},
    { RELOC_x86_64::R_X86_64_GOTPC32,         "GOTPC32"},
    { RELOC_x86_64::R_X86_64_GOT64,           "GOT64"},
    { RELOC_x86_64::R_X86_64_GOTPCREL64,      "GOTPCREL64"},
    { RELOC_x86_64::R_X86_64_GOTPC64,         "GOTPC64"},
    { RELOC_x86_64::R_X86_64_GOTPLT64,        "GOTPLT64"},
    { RELOC_x86_64::R_X86_64_PLTOFF64,        "PLTOFF64"},
    { RELOC_x86_64::R_X86_64_SIZE32,          "SIZE32"},
    { RELOC_x86_64::R_X86_64_SIZE64,          "SIZE64"},
    { RELOC_x86_64::R_X86_64_GOTPC32_TLSDESC, "GOTPC32_TLSDESC"},
    { RELOC_x86_64::R_X86_64_TLSDESC_CALL,    "TLSDESC_CALL"},
    { RELOC_x86_64::R_X86_64_TLSDESC,         "TLSDESC"},
    { RELOC_x86_64::R_X86_64_IRELATIVE,       "IRELATIVE"}
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(RELOC_ARM e) {
  const std::map<RELOC_ARM, const char*> enumStrings {
    { RELOC_ARM::R_ARM_NONE, "NONE"},
    { RELOC_ARM::R_ARM_PC24, "PC24"},
    { RELOC_ARM::R_ARM_ABS32, "ABS32"},
    { RELOC_ARM::R_ARM_REL32, "REL32"},
    { RELOC_ARM::R_ARM_LDR_PC_G0, "LDR_PC_G0"},
    { RELOC_ARM::R_ARM_ABS16, "ABS16"},
    { RELOC_ARM::R_ARM_ABS12, "ABS12"},
    { RELOC_ARM::R_ARM_THM_ABS5, "THM_ABS5"},
    { RELOC_ARM::R_ARM_ABS8, "ABS8"},
    { RELOC_ARM::R_ARM_SBREL32, "SBREL32"},
    { RELOC_ARM::R_ARM_THM_CALL, "THM_CALL"},
    { RELOC_ARM::R_ARM_THM_PC8, "THM_PC8"},
    { RELOC_ARM::R_ARM_BREL_ADJ, "BREL_ADJ"},
    { RELOC_ARM::R_ARM_TLS_DESC, "TLS_DESC"},
    { RELOC_ARM::R_ARM_THM_SWI8, "THM_SWI8"},
    { RELOC_ARM::R_ARM_XPC25, "XPC25"},
    { RELOC_ARM::R_ARM_THM_XPC22, "THM_XPC22"},
    { RELOC_ARM::R_ARM_TLS_DTPMOD32, "TLS_DTPMOD32"},
    { RELOC_ARM::R_ARM_TLS_DTPOFF32, "TLS_DTPOFF32"},
    { RELOC_ARM::R_ARM_TLS_TPOFF32, "TLS_TPOFF32"},
    { RELOC_ARM::R_ARM_COPY, "COPY"},
    { RELOC_ARM::R_ARM_GLOB_DAT, "GLOB_DAT"},
    { RELOC_ARM::R_ARM_JUMP_SLOT, "JUMP_SLOT"},
    { RELOC_ARM::R_ARM_RELATIVE, "RELATIVE"},
    { RELOC_ARM::R_ARM_GOTOFF32, "GOTOFF32"},
    { RELOC_ARM::R_ARM_BASE_PREL, "BASE_PREL"},
    { RELOC_ARM::R_ARM_GOT_BREL, "GOT_BREL"},
    { RELOC_ARM::R_ARM_PLT32, "PLT32"},
    { RELOC_ARM::R_ARM_CALL, "CALL"},
    { RELOC_ARM::R_ARM_JUMP24, "JUMP24"},
    { RELOC_ARM::R_ARM_THM_JUMP24, "THM_JUMP24"},
    { RELOC_ARM::R_ARM_BASE_ABS, "BASE_ABS"},
    { RELOC_ARM::R_ARM_ALU_PCREL_7_0, "ALU_PCREL_7_0"},
    { RELOC_ARM::R_ARM_ALU_PCREL_15_8, "ALU_PCREL_15_8"},
    { RELOC_ARM::R_ARM_ALU_PCREL_23_15, "ALU_PCREL_23_15"},
    { RELOC_ARM::R_ARM_LDR_SBREL_11_0_NC, "LDR_SBREL_11_0_NC"},
    { RELOC_ARM::R_ARM_ALU_SBREL_19_12_NC, "ALU_SBREL_19_12_NC"},
    { RELOC_ARM::R_ARM_ALU_SBREL_27_20_CK, "ALU_SBREL_27_20_CK"},
    { RELOC_ARM::R_ARM_TARGET1, "TARGET1"},
    { RELOC_ARM::R_ARM_SBREL31, "SBREL31"},
    { RELOC_ARM::R_ARM_V4BX, "V4BX"},
    { RELOC_ARM::R_ARM_TARGET2, "TARGET2"},
    { RELOC_ARM::R_ARM_PREL31, "PREL31"},
    { RELOC_ARM::R_ARM_MOVW_ABS_NC, "MOVW_ABS_NC"},
    { RELOC_ARM::R_ARM_MOVT_ABS, "MOVT_ABS"},
    { RELOC_ARM::R_ARM_MOVW_PREL_NC, "MOVW_PREL_NC"},
    { RELOC_ARM::R_ARM_MOVT_PREL, "MOVT_PREL"},
    { RELOC_ARM::R_ARM_THM_MOVW_ABS_NC, "THM_MOVW_ABS_NC"},
    { RELOC_ARM::R_ARM_THM_MOVT_ABS, "THM_MOVT_ABS"},
    { RELOC_ARM::R_ARM_THM_MOVW_PREL_NC, "THM_MOVW_PREL_NC"},
    { RELOC_ARM::R_ARM_THM_MOVT_PREL, "THM_MOVT_PREL"},
    { RELOC_ARM::R_ARM_THM_JUMP19, "THM_JUMP19"},
    { RELOC_ARM::R_ARM_THM_JUMP6, "THM_JUMP6"},
    { RELOC_ARM::R_ARM_THM_ALU_PREL_11_0, "THM_ALU_PREL_11_0"},
    { RELOC_ARM::R_ARM_THM_PC12, "THM_PC12"},
    { RELOC_ARM::R_ARM_ABS32_NOI, "ABS32_NOI"},
    { RELOC_ARM::R_ARM_REL32_NOI, "REL32_NOI"},
    { RELOC_ARM::R_ARM_ALU_PC_G0_NC, "ALU_PC_G0_NC"},
    { RELOC_ARM::R_ARM_ALU_PC_G0, "ALU_PC_G0"},
    { RELOC_ARM::R_ARM_ALU_PC_G1_NC, "ALU_PC_G1_NC"},
    { RELOC_ARM::R_ARM_ALU_PC_G1, "ALU_PC_G1"},
    { RELOC_ARM::R_ARM_ALU_PC_G2, "ALU_PC_G2"},
    { RELOC_ARM::R_ARM_LDR_PC_G1, "LDR_PC_G1"},
    { RELOC_ARM::R_ARM_LDR_PC_G2, "LDR_PC_G2"},
    { RELOC_ARM::R_ARM_LDRS_PC_G0, "LDRS_PC_G0"},
    { RELOC_ARM::R_ARM_LDRS_PC_G1, "LDRS_PC_G1"},
    { RELOC_ARM::R_ARM_LDRS_PC_G2, "LDRS_PC_G2"},
    { RELOC_ARM::R_ARM_LDC_PC_G0, "LDC_PC_G0"},
    { RELOC_ARM::R_ARM_LDC_PC_G1, "LDC_PC_G1"},
    { RELOC_ARM::R_ARM_LDC_PC_G2, "LDC_PC_G2"},
    { RELOC_ARM::R_ARM_ALU_SB_G0_NC, "ALU_SB_G0_NC"},
    { RELOC_ARM::R_ARM_ALU_SB_G0, "ALU_SB_G0"},
    { RELOC_ARM::R_ARM_ALU_SB_G1_NC, "ALU_SB_G1_NC"},
    { RELOC_ARM::R_ARM_ALU_SB_G1, "ALU_SB_G1"},
    { RELOC_ARM::R_ARM_ALU_SB_G2, "ALU_SB_G2"},
    { RELOC_ARM::R_ARM_LDR_SB_G0, "LDR_SB_G0"},
    { RELOC_ARM::R_ARM_LDR_SB_G1, "LDR_SB_G1"},
    { RELOC_ARM::R_ARM_LDR_SB_G2, "LDR_SB_G2"},
    { RELOC_ARM::R_ARM_LDRS_SB_G0, "LDRS_SB_G0"},
    { RELOC_ARM::R_ARM_LDRS_SB_G1, "LDRS_SB_G1"},
    { RELOC_ARM::R_ARM_LDRS_SB_G2, "LDRS_SB_G2"},
    { RELOC_ARM::R_ARM_LDC_SB_G0, "LDC_SB_G0"},
    { RELOC_ARM::R_ARM_LDC_SB_G1, "LDC_SB_G1"},
    { RELOC_ARM::R_ARM_LDC_SB_G2, "LDC_SB_G2"},
    { RELOC_ARM::R_ARM_MOVW_BREL_NC, "MOVW_BREL_NC"},
    { RELOC_ARM::R_ARM_MOVT_BREL, "MOVT_BREL"},
    { RELOC_ARM::R_ARM_MOVW_BREL, "MOVW_BREL"},
    { RELOC_ARM::R_ARM_THM_MOVW_BREL_NC, "THM_MOVW_BREL_NC"},
    { RELOC_ARM::R_ARM_THM_MOVT_BREL, "THM_MOVT_BREL"},
    { RELOC_ARM::R_ARM_THM_MOVW_BREL, "THM_MOVW_BREL"},
    { RELOC_ARM::R_ARM_TLS_GOTDESC, "TLS_GOTDESC"},
    { RELOC_ARM::R_ARM_TLS_CALL, "TLS_CALL"},
    { RELOC_ARM::R_ARM_TLS_DESCSEQ, "TLS_DESCSEQ"},
    { RELOC_ARM::R_ARM_THM_TLS_CALL, "THM_TLS_CALL"},
    { RELOC_ARM::R_ARM_PLT32_ABS, "PLT32_ABS"},
    { RELOC_ARM::R_ARM_GOT_ABS, "GOT_ABS"},
    { RELOC_ARM::R_ARM_GOT_PREL, "GOT_PREL"},
    { RELOC_ARM::R_ARM_GOT_BREL12, "GOT_BREL12"},
    { RELOC_ARM::R_ARM_GOTOFF12, "GOTOFF12"},
    { RELOC_ARM::R_ARM_GOTRELAX, "GOTRELAX"},
    { RELOC_ARM::R_ARM_GNU_VTENTRY, "GNU_VTENTRY"},
    { RELOC_ARM::R_ARM_GNU_VTINHERIT, "GNU_VTINHERIT"},
    { RELOC_ARM::R_ARM_THM_JUMP11, "THM_JUMP11"},
    { RELOC_ARM::R_ARM_THM_JUMP8, "THM_JUMP8"},
    { RELOC_ARM::R_ARM_TLS_GD32, "TLS_GD32"},
    { RELOC_ARM::R_ARM_TLS_LDM32, "TLS_LDM32"},
    { RELOC_ARM::R_ARM_TLS_LDO32, "TLS_LDO32"},
    { RELOC_ARM::R_ARM_TLS_IE32, "TLS_IE32"},
    { RELOC_ARM::R_ARM_TLS_LE32, "TLS_LE32"},
    { RELOC_ARM::R_ARM_TLS_LDO12, "TLS_LDO12"},
    { RELOC_ARM::R_ARM_TLS_LE12, "TLS_LE12"},
    { RELOC_ARM::R_ARM_TLS_IE12GP, "TLS_IE12GP"},
    { RELOC_ARM::R_ARM_PRIVATE_0, "PRIVATE_0"},
    { RELOC_ARM::R_ARM_PRIVATE_1, "PRIVATE_1"},
    { RELOC_ARM::R_ARM_PRIVATE_2, "PRIVATE_2"},
    { RELOC_ARM::R_ARM_PRIVATE_3, "PRIVATE_3"},
    { RELOC_ARM::R_ARM_PRIVATE_4, "PRIVATE_4"},
    { RELOC_ARM::R_ARM_PRIVATE_5, "PRIVATE_5"},
    { RELOC_ARM::R_ARM_PRIVATE_6, "PRIVATE_6"},
    { RELOC_ARM::R_ARM_PRIVATE_7, "PRIVATE_7"},
    { RELOC_ARM::R_ARM_PRIVATE_8, "PRIVATE_8"},
    { RELOC_ARM::R_ARM_PRIVATE_9, "PRIVATE_9"},
    { RELOC_ARM::R_ARM_PRIVATE_10, "PRIVATE_10"},
    { RELOC_ARM::R_ARM_PRIVATE_11, "PRIVATE_11"},
    { RELOC_ARM::R_ARM_PRIVATE_12, "PRIVATE_12"},
    { RELOC_ARM::R_ARM_PRIVATE_13, "PRIVATE_13"},
    { RELOC_ARM::R_ARM_PRIVATE_14, "PRIVATE_14"},
    { RELOC_ARM::R_ARM_PRIVATE_15, "PRIVATE_15"},
    { RELOC_ARM::R_ARM_ME_TOO, "ME_TOO"},
    { RELOC_ARM::R_ARM_THM_TLS_DESCSEQ16, "THM_TLS_DESCSEQ16"},
    { RELOC_ARM::R_ARM_THM_TLS_DESCSEQ32, "THM_TLS_DESCSEQ32"},
    { RELOC_ARM::R_ARM_IRELATIVE, "IRELATIVE"}
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(RELOC_i386 e) {
  const std::map<RELOC_i386, const char*> enumStrings {
    { RELOC_i386::R_386_NONE, "NONE"},
    { RELOC_i386::R_386_32, "32"},
    { RELOC_i386::R_386_PC32, "PC32"},
    { RELOC_i386::R_386_GOT32, "GOT32"},
    { RELOC_i386::R_386_PLT32, "PLT32"},
    { RELOC_i386::R_386_COPY, "COPY"},
    { RELOC_i386::R_386_GLOB_DAT, "GLOB_DAT"},
    { RELOC_i386::R_386_JUMP_SLOT, "JUMP_SLOT"},
    { RELOC_i386::R_386_RELATIVE, "RELATIVE"},
    { RELOC_i386::R_386_GOTOFF, "GOTOFF"},
    { RELOC_i386::R_386_GOTPC, "GOTPC"},
    { RELOC_i386::R_386_32PLT, "32PLT"},
    { RELOC_i386::R_386_TLS_TPOFF, "TLS_TPOFF"},
    { RELOC_i386::R_386_TLS_IE, "TLS_IE"},
    { RELOC_i386::R_386_TLS_GOTIE, "TLS_GOTIE"},
    { RELOC_i386::R_386_TLS_LE, "TLS_LE"},
    { RELOC_i386::R_386_TLS_GD, "TLS_GD"},
    { RELOC_i386::R_386_TLS_LDM, "TLS_LDM"},
    { RELOC_i386::R_386_16, "16"},
    { RELOC_i386::R_386_PC16, "PC16"},
    { RELOC_i386::R_386_8, "8"},
    { RELOC_i386::R_386_PC8, "PC8"},
    { RELOC_i386::R_386_TLS_GD_32, "TLS_GD_32"},
    { RELOC_i386::R_386_TLS_GD_PUSH, "TLS_GD_PUSH"},
    { RELOC_i386::R_386_TLS_GD_CALL, "TLS_GD_CALL"},
    { RELOC_i386::R_386_TLS_GD_POP, "TLS_GD_POP"},
    { RELOC_i386::R_386_TLS_LDM_32, "TLS_LDM_32"},
    { RELOC_i386::R_386_TLS_LDM_PUSH, "TLS_LDM_PUSH"},
    { RELOC_i386::R_386_TLS_LDM_CALL, "TLS_LDM_CALL"},
    { RELOC_i386::R_386_TLS_LDM_POP, "TLS_LDM_POP"},
    { RELOC_i386::R_386_TLS_LDO_32, "TLS_LDO_32"},
    { RELOC_i386::R_386_TLS_IE_32, "TLS_IE_32"},
    { RELOC_i386::R_386_TLS_LE_32, "TLS_LE_32"},
    { RELOC_i386::R_386_TLS_DTPMOD32, "TLS_DTPMOD32"},
    { RELOC_i386::R_386_TLS_DTPOFF32, "TLS_DTPOFF32"},
    { RELOC_i386::R_386_TLS_TPOFF32, "TLS_TPOFF32"},
    { RELOC_i386::R_386_TLS_GOTDESC, "TLS_GOTDESC"},
    { RELOC_i386::R_386_TLS_DESC_CALL, "TLS_DESC_CALL"},
    { RELOC_i386::R_386_TLS_DESC, "TLS_DESC"},
    { RELOC_i386::R_386_IRELATIVE, "IRELATIVE"},
    { RELOC_i386::R_386_NUM, "NUM"},
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(ELF_CLASS e) {
  const std::map<ELF_CLASS, const char*> enumStrings {
    { ELF_CLASS::ELFCLASSNONE, "NONE"},
    { ELF_CLASS::ELFCLASS32,   "CLASS32"},
    { ELF_CLASS::ELFCLASS64,   "CLASS64"},
  };

  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(ELF_DATA e) {
  const std::map<ELF_DATA, const char*> enumStrings {
    { ELF_DATA::ELFDATANONE, "NONE"},
    { ELF_DATA::ELFDATA2LSB, "LSB"},
    { ELF_DATA::ELFDATA2MSB, "MSB"},
  };

  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(OS_ABI e) {
  const std::map<OS_ABI, const char*> enumStrings {
    { OS_ABI::ELFOSABI_SYSTEMV,      "SYSTEMV"},
    { OS_ABI::ELFOSABI_HPUX,         "HPUX"},
    { OS_ABI::ELFOSABI_NETBSD,       "NETBSD"},
    { OS_ABI::ELFOSABI_GNU,          "GNU"},
    { OS_ABI::ELFOSABI_LINUX,        "LINUX"},
    { OS_ABI::ELFOSABI_HURD,         "HURD"},
    { OS_ABI::ELFOSABI_SOLARIS,      "SOLARIS"},
    { OS_ABI::ELFOSABI_AIX,          "AIX"},
    { OS_ABI::ELFOSABI_IRIX,         "IRIX"},
    { OS_ABI::ELFOSABI_FREEBSD,      "FREEBSD"},
    { OS_ABI::ELFOSABI_TRU64,        "TRU64"},
    { OS_ABI::ELFOSABI_MODESTO,      "MODESTO"},
    { OS_ABI::ELFOSABI_OPENBSD,      "OPENBSD"},
    { OS_ABI::ELFOSABI_OPENVMS,      "OPENVMS"},
    { OS_ABI::ELFOSABI_NSK,          "NSK"},
    { OS_ABI::ELFOSABI_AROS,         "AROS"},
    { OS_ABI::ELFOSABI_FENIXOS,      "FENIXOS"},
    { OS_ABI::ELFOSABI_CLOUDABI,     "CLOUDABI"},
    { OS_ABI::ELFOSABI_C6000_ELFABI, "C6000_ELFABI"},
    { OS_ABI::ELFOSABI_AMDGPU_HSA,   "AMDGPU_HSA"},
    { OS_ABI::ELFOSABI_C6000_LINUX,  "C6000_LINUX"},
    { OS_ABI::ELFOSABI_ARM,          "ARM"},
    { OS_ABI::ELFOSABI_STANDALONE,   "STANDALONE"},
  };

  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(DYNSYM_COUNT_METHODS e) {
  const std::map<DYNSYM_COUNT_METHODS, const char*> enumStrings {
    { DYNSYM_COUNT_METHODS::COUNT_AUTO,        "AUTO"},
    { DYNSYM_COUNT_METHODS::COUNT_SECTION,     "SECTION"},
    { DYNSYM_COUNT_METHODS::COUNT_HASH,        "HASH"},
    { DYNSYM_COUNT_METHODS::COUNT_RELOCATIONS, "RELOCATIONS"},
  };

  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}
} // namespace ELF
} // namespace LIEF



