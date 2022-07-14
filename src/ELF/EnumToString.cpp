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
#include "LIEF/ELF/EnumToString.hpp"
#include "LIEF/ELF/NoteDetails/core/CorePrStatus.hpp"
#include "frozen.hpp"
#include <map>

namespace LIEF {
namespace ELF {

const char* to_string(SYMBOL_BINDINGS e) {
  CONST_MAP(SYMBOL_BINDINGS, const char*, 4) enumStrings {
    { SYMBOL_BINDINGS::STB_LOCAL,      "LOCAL" },
    { SYMBOL_BINDINGS::STB_GLOBAL,     "GLOBAL" },
    { SYMBOL_BINDINGS::STB_WEAK,       "WEAK" },
    { SYMBOL_BINDINGS::STB_GNU_UNIQUE, "GNU_UNIQUE" },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(E_TYPE e) {
  CONST_MAP(E_TYPE, const char*, 7) enumStrings {
    { E_TYPE::ET_NONE,   "NONE" },
    { E_TYPE::ET_REL,    "RELOCATABLE" },
    { E_TYPE::ET_EXEC,   "EXECUTABLE" },
    { E_TYPE::ET_DYN,    "DYNAMIC" },
    { E_TYPE::ET_CORE,   "CORE" },
    { E_TYPE::ET_LOPROC, "LOPROC" },
    { E_TYPE::ET_HIPROC, "HIPROC" }
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(VERSION e) {
  CONST_MAP(VERSION, const char*, 2) enumStrings {
    { VERSION::EV_NONE,    "NONE" },
    { VERSION::EV_CURRENT, "CURRENT" }
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(ARCH e) {
  CONST_MAP(ARCH, const char*, 177) enumStrings {
    { ARCH::EM_NONE,          "NONE" },
    { ARCH::EM_M32,           "M32"},
    { ARCH::EM_SPARC,         "SPARC"},
    { ARCH::EM_386,           "i386"},
    { ARCH::EM_68K,           "ARCH_68K"},
    { ARCH::EM_88K,           "ARCH_88K"},
    { ARCH::EM_IAMCU,         "IAMCU"},
    { ARCH::EM_860,           "ARCH_860"},
    { ARCH::EM_MIPS,          "MIPS"},
    { ARCH::EM_S370,          "S370"},
    { ARCH::EM_MIPS_RS3_LE,   "MIPS_RS3_LE"},
    { ARCH::EM_PARISC,        "PARISC"},
    { ARCH::EM_VPP500,        "VPP500"},
    { ARCH::EM_SPARC32PLUS,   "SPARC32PLUS"},
    { ARCH::EM_960,           "ARCH_960"},
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
    { ARCH::EM_68HC12,        "ARCH_68HC12"},
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
    { ARCH::EM_68HC16,        "ARCH_68HC16"},
    { ARCH::EM_68HC11,        "ARCH_68HC11"},
    { ARCH::EM_68HC08,        "ARCH_68HC08"},
    { ARCH::EM_68HC05,        "ARCH_68HC05"},
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
    { ARCH::EM_8051,          "ARCH_8051"},
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
    { ARCH::EM_78KOR,         "ARCH_78KOR"},
    { ARCH::EM_56800EX,       "ARCH_56800EX"},
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
    { ARCH::EM_AMDGPU,        "AMDGPU"},
    { ARCH::EM_RISCV,         "RISCV"},
    { ARCH::EM_BPF,           "BPF"}
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(SEGMENT_TYPES e) {
  CONST_MAP(SEGMENT_TYPES, const char*, 20) enumStrings {
    { SEGMENT_TYPES::PT_NULL,          "NULL" },
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
    //{ SEGMENT_TYPES::PT_SUNW_EH_FRAME, "SUNW_EH_FRAME" },
    { SEGMENT_TYPES::PT_SUNW_UNWIND,   "SUNW_UNWIND" },
    { SEGMENT_TYPES::PT_GNU_STACK,     "GNU_STACK" },
    { SEGMENT_TYPES::PT_GNU_PROPERTY,  "GNU_PROPERTY" },
    { SEGMENT_TYPES::PT_GNU_RELRO,     "GNU_RELRO" },
    { SEGMENT_TYPES::PT_ARM_ARCHEXT,   "ARM_ARCHEXT" },
    { SEGMENT_TYPES::PT_ARM_EXIDX,     "ARM_EXIDX" },
    { SEGMENT_TYPES::PT_ARM_UNWIND,    "ARM_UNWIND" },
    //{ SEGMENT_TYPES::PT_MIPS_REGINFO,  "MIPS_REGINFO" },
    //{ SEGMENT_TYPES::PT_MIPS_RTPROC,   "MIPS_RTPROC" },
    //{ SEGMENT_TYPES::PT_MIPS_OPTIONS,  "MIPS_OPTIONS" },
    //{ SEGMENT_TYPES::PT_MIPS_ABIFLAGS, "MIPS_ABIFLAGS" }
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(DYNAMIC_TAGS e) {
  CONST_MAP(DYNAMIC_TAGS, const char*, 97) enumStrings {
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
    //{ DYNAMIC_TAGS::DT_ENCODING,                   "ENCODING"}, // SKIPED
    { DYNAMIC_TAGS::DT_PREINIT_ARRAY,              "PREINIT_ARRAY"},
    { DYNAMIC_TAGS::DT_PREINIT_ARRAYSZ,            "PREINIT_ARRAYSZ"},
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
    { DYNAMIC_TAGS::DT_MIPS_RWPLT,                 "MIPS_RWPLT"},
    { DYNAMIC_TAGS::DT_ANDROID_REL_OFFSET,         "ANDROID_REL_OFFSET"},
    { DYNAMIC_TAGS::DT_ANDROID_REL_SIZE,           "ANDROID_REL_SIZE"},
    { DYNAMIC_TAGS::DT_ANDROID_REL,                "ANDROID_REL"},
    { DYNAMIC_TAGS::DT_ANDROID_RELSZ,              "ANDROID_RELSZ"},
    { DYNAMIC_TAGS::DT_ANDROID_RELA,               "ANDROID_RELA"},
    { DYNAMIC_TAGS::DT_ANDROID_RELASZ,             "ANDROID_RELASZ"},
    { DYNAMIC_TAGS::DT_RELR,                       "RELR"},
    { DYNAMIC_TAGS::DT_RELRSZ,                     "RELRSZ"},
    { DYNAMIC_TAGS::DT_RELRENT,                    "RELRENT"},
    { DYNAMIC_TAGS::DT_RELRCOUNT,                  "RELRCOUNT"}
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(ELF_SECTION_TYPES e) {
  CONST_MAP(ELF_SECTION_TYPES, const char*, 39) enumStrings {
    { ELF_SECTION_TYPES::SHT_NULL,               "NULL"},
    { ELF_SECTION_TYPES::SHT_PROGBITS,           "PROGBITS"},
    { ELF_SECTION_TYPES::SHT_SYMTAB,             "SYMTAB"},
    { ELF_SECTION_TYPES::SHT_STRTAB,             "STRTAB"},
    { ELF_SECTION_TYPES::SHT_RELA,               "RELA"},
    { ELF_SECTION_TYPES::SHT_HASH,               "HASH"},
    { ELF_SECTION_TYPES::SHT_DYNAMIC,            "DYNAMIC"},
    { ELF_SECTION_TYPES::SHT_NOTE,               "NOTE"},
    { ELF_SECTION_TYPES::SHT_NOBITS,             "NOBITS"},
    { ELF_SECTION_TYPES::SHT_REL,                "REL"},
    { ELF_SECTION_TYPES::SHT_SHLIB,              "SHLIB"},
    { ELF_SECTION_TYPES::SHT_DYNSYM,             "DYNSYM"},
    { ELF_SECTION_TYPES::SHT_INIT_ARRAY,         "INIT_ARRAY"},
    { ELF_SECTION_TYPES::SHT_FINI_ARRAY,         "FINI_ARRAY"},
    { ELF_SECTION_TYPES::SHT_PREINIT_ARRAY,      "PREINIT_ARRAY"},
    { ELF_SECTION_TYPES::SHT_GROUP,              "GROUP"},
    { ELF_SECTION_TYPES::SHT_SYMTAB_SHNDX,       "SYMTAB_SHNDX"},
    { ELF_SECTION_TYPES::SHT_LOOS,               "LOOS"},
    { ELF_SECTION_TYPES::SHT_ANDROID_REL,        "ANDROID_REL"},
    { ELF_SECTION_TYPES::SHT_ANDROID_RELA,       "ANDROID_RELA"},
    { ELF_SECTION_TYPES::SHT_LLVM_ADDRSIG,       "LLVM_ADDRSIG"},
    { ELF_SECTION_TYPES::SHT_RELR,               "RELR"},
    { ELF_SECTION_TYPES::SHT_GNU_ATTRIBUTES,     "GNU_ATTRIBUTES"},
    { ELF_SECTION_TYPES::SHT_GNU_HASH,           "GNU_HASH"},
    { ELF_SECTION_TYPES::SHT_GNU_verdef,         "GNU_VERDEF"},
    { ELF_SECTION_TYPES::SHT_GNU_verneed,        "GNU_VERNEED"},
    { ELF_SECTION_TYPES::SHT_GNU_versym,         "GNU_VERSYM"},
    { ELF_SECTION_TYPES::SHT_HIOS,               "HIOS"},
    { ELF_SECTION_TYPES::SHT_LOPROC,             "LOPROC"},
    { ELF_SECTION_TYPES::SHT_ARM_EXIDX,          "ARM_EXIDX"},
    { ELF_SECTION_TYPES::SHT_ARM_PREEMPTMAP,     "ARM_PREEMPTMAP"},
    { ELF_SECTION_TYPES::SHT_ARM_ATTRIBUTES,     "ARM_ATTRIBUTES"},
    { ELF_SECTION_TYPES::SHT_ARM_DEBUGOVERLAY,   "ARM_DEBUGOVERLAY"},
    { ELF_SECTION_TYPES::SHT_ARM_OVERLAYSECTION, "ARM_OVERLAYSECTION"},
    { ELF_SECTION_TYPES::SHT_HEX_ORDERED,        "HEX_ORDERED"},
    { ELF_SECTION_TYPES::SHT_X86_64_UNWIND,      "X86_64_UNWIND"},
    //{ ELF_SECTION_TYPES::SHT_MIPS_REGINFO,       "MIPS_REGINFO"},
    //{ ELF_SECTION_TYPES::SHT_MIPS_OPTIONS,       "MIPS_OPTIONS"},
    //{ ELF_SECTION_TYPES::SHT_MIPS_ABIFLAGS,      "MIPS_ABIFLAGS"},
    { ELF_SECTION_TYPES::SHT_HIPROC,             "HIPROC"},
    { ELF_SECTION_TYPES::SHT_LOUSER,             "LOUSER"},
    { ELF_SECTION_TYPES::SHT_HIUSER,             "HIUSER"}
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(ELF_SECTION_FLAGS e) {
  CONST_MAP(ELF_SECTION_FLAGS, const char*, 25) enumStrings {
    { ELF_SECTION_FLAGS::SHF_NONE,             "NONE"},
    { ELF_SECTION_FLAGS::SHF_WRITE,            "WRITE"},
    { ELF_SECTION_FLAGS::SHF_ALLOC,            "ALLOC"},
    { ELF_SECTION_FLAGS::SHF_EXECINSTR,        "EXECINSTR"},
    { ELF_SECTION_FLAGS::SHF_MERGE,            "MERGE"},
    { ELF_SECTION_FLAGS::SHF_STRINGS,          "STRINGS"},
    { ELF_SECTION_FLAGS::SHF_INFO_LINK,        "INFO_LINK"},
    { ELF_SECTION_FLAGS::SHF_LINK_ORDER,       "LINK_ORDER"},
    { ELF_SECTION_FLAGS::SHF_OS_NONCONFORMING, "OS_NONCONFORMING"},
    { ELF_SECTION_FLAGS::SHF_GROUP,            "GROUP"},
    { ELF_SECTION_FLAGS::SHF_TLS,              "TLS"},
    { ELF_SECTION_FLAGS::SHF_EXCLUDE,          "EXCLUDE"},
    { ELF_SECTION_FLAGS::XCORE_SHF_CP_SECTION, "XCORE_SHF_CP_SECTION"},
    { ELF_SECTION_FLAGS::XCORE_SHF_DP_SECTION, "XCORE_SHF_CP_SECTION"},
    { ELF_SECTION_FLAGS::SHF_MASKOS,           "MASKOS"},
    { ELF_SECTION_FLAGS::SHF_MASKPROC,         "MASKPROC"},
    { ELF_SECTION_FLAGS::SHF_HEX_GPREL,        "HEX_GPREL"},
    { ELF_SECTION_FLAGS::SHF_MIPS_NODUPES,     "MIPS_NODUPES"},
    { ELF_SECTION_FLAGS::SHF_MIPS_NAMES,       "MIPS_NAMES"},
    { ELF_SECTION_FLAGS::SHF_MIPS_LOCAL,       "MIPS_LOCAL"},
    { ELF_SECTION_FLAGS::SHF_MIPS_NOSTRIP,     "MIPS_NOSTRIP"},
    { ELF_SECTION_FLAGS::SHF_MIPS_GPREL,       "MIPS_GPREL"},
    { ELF_SECTION_FLAGS::SHF_MIPS_MERGE,       "MIPS_MERGE"},
    { ELF_SECTION_FLAGS::SHF_MIPS_ADDR,        "MIPS_ADDR"},
    { ELF_SECTION_FLAGS::SHF_MIPS_STRING,      "MIPS_STRING"}
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(ELF_SYMBOL_TYPES e) {
  CONST_MAP(ELF_SYMBOL_TYPES, const char*, 8) enumStrings {
    { ELF_SYMBOL_TYPES::STT_NOTYPE,    "NOTYPE"},
    { ELF_SYMBOL_TYPES::STT_OBJECT,    "OBJECT"},
    { ELF_SYMBOL_TYPES::STT_FUNC,      "FUNC"},
    { ELF_SYMBOL_TYPES::STT_SECTION,   "SECTION"},
    { ELF_SYMBOL_TYPES::STT_FILE,      "FILE"},
    { ELF_SYMBOL_TYPES::STT_COMMON,    "COMMON"},
    { ELF_SYMBOL_TYPES::STT_TLS,       "TLS"},
    { ELF_SYMBOL_TYPES::STT_GNU_IFUNC, "GNU_IFUNC"},
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(RELOC_x86_64 e) {
  CONST_MAP(RELOC_x86_64, const char*, 43) enumStrings {
    { RELOC_x86_64::R_X86_64_NONE,            "NONE"},
    { RELOC_x86_64::R_X86_64_64,              "R64"},
    { RELOC_x86_64::R_X86_64_PC32,            "PC32"},
    { RELOC_x86_64::R_X86_64_GOT32,           "GOT32"},
    { RELOC_x86_64::R_X86_64_PLT32,           "PLT32"},
    { RELOC_x86_64::R_X86_64_COPY,            "COPY"},
    { RELOC_x86_64::R_X86_64_GLOB_DAT,        "GLOB_DAT"},
    { RELOC_x86_64::R_X86_64_JUMP_SLOT,       "JUMP_SLOT"},
    { RELOC_x86_64::R_X86_64_RELATIVE,        "RELATIVE"},
    { RELOC_x86_64::R_X86_64_GOTPCREL,        "GOTPCREL"},
    { RELOC_x86_64::R_X86_64_32,              "R32"},
    { RELOC_x86_64::R_X86_64_32S,             "R32S"},
    { RELOC_x86_64::R_X86_64_16,              "R16"},
    { RELOC_x86_64::R_X86_64_PC16,            "PC16"},
    { RELOC_x86_64::R_X86_64_8,               "R8"},
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
    { RELOC_x86_64::R_X86_64_IRELATIVE,       "IRELATIVE"},
    { RELOC_x86_64::R_X86_64_RELATIVE64,      "RELATIVE64"},
    { RELOC_x86_64::R_X86_64_PC32_BND,        "PC32_BND"},
    { RELOC_x86_64::R_X86_64_PLT32_BND,       "PLT32_BND"},
    { RELOC_x86_64::R_X86_64_GOTPCRELX,       "GOTPCRELX"},
    { RELOC_x86_64::R_X86_64_REX_GOTPCRELX,   "REX_GOTPCRELX"},
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(RELOC_ARM e) {
  CONST_MAP(RELOC_ARM, const char*, 138) enumStrings {
    { RELOC_ARM::R_ARM_NONE,               "NONE"},
    { RELOC_ARM::R_ARM_PC24,               "PC24"},
    { RELOC_ARM::R_ARM_ABS32,              "ABS32"},
    { RELOC_ARM::R_ARM_REL32,              "REL32"},
    { RELOC_ARM::R_ARM_LDR_PC_G0,          "LDR_PC_G0"},
    { RELOC_ARM::R_ARM_ABS16,              "ABS16"},
    { RELOC_ARM::R_ARM_ABS12,              "ABS12"},
    { RELOC_ARM::R_ARM_THM_ABS5,           "THM_ABS5"},
    { RELOC_ARM::R_ARM_ABS8,               "ABS8"},
    { RELOC_ARM::R_ARM_SBREL32,            "SBREL32"},
    { RELOC_ARM::R_ARM_THM_CALL,           "THM_CALL"},
    { RELOC_ARM::R_ARM_THM_PC8,            "THM_PC8"},
    { RELOC_ARM::R_ARM_BREL_ADJ,           "BREL_ADJ"},
    { RELOC_ARM::R_ARM_TLS_DESC,           "TLS_DESC"},
    { RELOC_ARM::R_ARM_THM_SWI8,           "THM_SWI8"},
    { RELOC_ARM::R_ARM_XPC25,              "XPC25"},
    { RELOC_ARM::R_ARM_THM_XPC22,          "THM_XPC22"},
    { RELOC_ARM::R_ARM_TLS_DTPMOD32,       "TLS_DTPMOD32"},
    { RELOC_ARM::R_ARM_TLS_DTPOFF32,       "TLS_DTPOFF32"},
    { RELOC_ARM::R_ARM_TLS_TPOFF32,        "TLS_TPOFF32"},
    { RELOC_ARM::R_ARM_COPY,               "COPY"},
    { RELOC_ARM::R_ARM_GLOB_DAT,           "GLOB_DAT"},
    { RELOC_ARM::R_ARM_JUMP_SLOT,          "JUMP_SLOT"},
    { RELOC_ARM::R_ARM_RELATIVE,           "RELATIVE"},
    { RELOC_ARM::R_ARM_GOTOFF32,           "GOTOFF32"},
    { RELOC_ARM::R_ARM_BASE_PREL,          "BASE_PREL"},
    { RELOC_ARM::R_ARM_GOT_BREL,           "GOT_BREL"},
    { RELOC_ARM::R_ARM_PLT32,              "PLT32"},
    { RELOC_ARM::R_ARM_CALL,               "CALL"},
    { RELOC_ARM::R_ARM_JUMP24,             "JUMP24"},
    { RELOC_ARM::R_ARM_THM_JUMP24,         "THM_JUMP24"},
    { RELOC_ARM::R_ARM_BASE_ABS,           "BASE_ABS"},
    { RELOC_ARM::R_ARM_ALU_PCREL_7_0,      "ALU_PCREL_7_0"},
    { RELOC_ARM::R_ARM_ALU_PCREL_15_8,     "ALU_PCREL_15_8"},
    { RELOC_ARM::R_ARM_ALU_PCREL_23_15,    "ALU_PCREL_23_15"},
    { RELOC_ARM::R_ARM_LDR_SBREL_11_0_NC,  "LDR_SBREL_11_0_NC"},
    { RELOC_ARM::R_ARM_ALU_SBREL_19_12_NC, "ALU_SBREL_19_12_NC"},
    { RELOC_ARM::R_ARM_ALU_SBREL_27_20_CK, "ALU_SBREL_27_20_CK"},
    { RELOC_ARM::R_ARM_TARGET1,            "TARGET1"},
    { RELOC_ARM::R_ARM_SBREL31,            "SBREL31"},
    { RELOC_ARM::R_ARM_V4BX,               "V4BX"},
    { RELOC_ARM::R_ARM_TARGET2,            "TARGET2"},
    { RELOC_ARM::R_ARM_PREL31,             "PREL31"},
    { RELOC_ARM::R_ARM_MOVW_ABS_NC,        "MOVW_ABS_NC"},
    { RELOC_ARM::R_ARM_MOVT_ABS,           "MOVT_ABS"},
    { RELOC_ARM::R_ARM_MOVW_PREL_NC,       "MOVW_PREL_NC"},
    { RELOC_ARM::R_ARM_MOVT_PREL,          "MOVT_PREL"},
    { RELOC_ARM::R_ARM_THM_MOVW_ABS_NC,    "THM_MOVW_ABS_NC"},
    { RELOC_ARM::R_ARM_THM_MOVT_ABS,       "THM_MOVT_ABS"},
    { RELOC_ARM::R_ARM_THM_MOVW_PREL_NC,   "THM_MOVW_PREL_NC"},
    { RELOC_ARM::R_ARM_THM_MOVT_PREL,      "THM_MOVT_PREL"},
    { RELOC_ARM::R_ARM_THM_JUMP19,         "THM_JUMP19"},
    { RELOC_ARM::R_ARM_THM_JUMP6,          "THM_JUMP6"},
    { RELOC_ARM::R_ARM_THM_ALU_PREL_11_0,  "THM_ALU_PREL_11_0"},
    { RELOC_ARM::R_ARM_THM_PC12,           "THM_PC12"},
    { RELOC_ARM::R_ARM_ABS32_NOI,          "ABS32_NOI"},
    { RELOC_ARM::R_ARM_REL32_NOI,          "REL32_NOI"},
    { RELOC_ARM::R_ARM_ALU_PC_G0_NC,       "ALU_PC_G0_NC"},
    { RELOC_ARM::R_ARM_ALU_PC_G0,          "ALU_PC_G0"},
    { RELOC_ARM::R_ARM_ALU_PC_G1_NC,       "ALU_PC_G1_NC"},
    { RELOC_ARM::R_ARM_ALU_PC_G1,          "ALU_PC_G1"},
    { RELOC_ARM::R_ARM_ALU_PC_G2,          "ALU_PC_G2"},
    { RELOC_ARM::R_ARM_LDR_PC_G1,          "LDR_PC_G1"},
    { RELOC_ARM::R_ARM_LDR_PC_G2,          "LDR_PC_G2"},
    { RELOC_ARM::R_ARM_LDRS_PC_G0,         "LDRS_PC_G0"},
    { RELOC_ARM::R_ARM_LDRS_PC_G1,         "LDRS_PC_G1"},
    { RELOC_ARM::R_ARM_LDRS_PC_G2,         "LDRS_PC_G2"},
    { RELOC_ARM::R_ARM_LDC_PC_G0,          "LDC_PC_G0"},
    { RELOC_ARM::R_ARM_LDC_PC_G1,          "LDC_PC_G1"},
    { RELOC_ARM::R_ARM_LDC_PC_G2,          "LDC_PC_G2"},
    { RELOC_ARM::R_ARM_ALU_SB_G0_NC,       "ALU_SB_G0_NC"},
    { RELOC_ARM::R_ARM_ALU_SB_G0,          "ALU_SB_G0"},
    { RELOC_ARM::R_ARM_ALU_SB_G1_NC,       "ALU_SB_G1_NC"},
    { RELOC_ARM::R_ARM_ALU_SB_G1,          "ALU_SB_G1"},
    { RELOC_ARM::R_ARM_ALU_SB_G2,          "ALU_SB_G2"},
    { RELOC_ARM::R_ARM_LDR_SB_G0,          "LDR_SB_G0"},
    { RELOC_ARM::R_ARM_LDR_SB_G1,          "LDR_SB_G1"},
    { RELOC_ARM::R_ARM_LDR_SB_G2,          "LDR_SB_G2"},
    { RELOC_ARM::R_ARM_LDRS_SB_G0,         "LDRS_SB_G0"},
    { RELOC_ARM::R_ARM_LDRS_SB_G1,         "LDRS_SB_G1"},
    { RELOC_ARM::R_ARM_LDRS_SB_G2,         "LDRS_SB_G2"},
    { RELOC_ARM::R_ARM_LDC_SB_G0,          "LDC_SB_G0"},
    { RELOC_ARM::R_ARM_LDC_SB_G1,          "LDC_SB_G1"},
    { RELOC_ARM::R_ARM_LDC_SB_G2,          "LDC_SB_G2"},
    { RELOC_ARM::R_ARM_MOVW_BREL_NC,       "MOVW_BREL_NC"},
    { RELOC_ARM::R_ARM_MOVT_BREL,          "MOVT_BREL"},
    { RELOC_ARM::R_ARM_MOVW_BREL,          "MOVW_BREL"},
    { RELOC_ARM::R_ARM_THM_MOVW_BREL_NC,   "THM_MOVW_BREL_NC"},
    { RELOC_ARM::R_ARM_THM_MOVT_BREL,      "THM_MOVT_BREL"},
    { RELOC_ARM::R_ARM_THM_MOVW_BREL,      "THM_MOVW_BREL"},
    { RELOC_ARM::R_ARM_TLS_GOTDESC,        "TLS_GOTDESC"},
    { RELOC_ARM::R_ARM_TLS_CALL,           "TLS_CALL"},
    { RELOC_ARM::R_ARM_TLS_DESCSEQ,        "TLS_DESCSEQ"},
    { RELOC_ARM::R_ARM_THM_TLS_CALL,       "THM_TLS_CALL"},
    { RELOC_ARM::R_ARM_PLT32_ABS,          "PLT32_ABS"},
    { RELOC_ARM::R_ARM_GOT_ABS,            "GOT_ABS"},
    { RELOC_ARM::R_ARM_GOT_PREL,           "GOT_PREL"},
    { RELOC_ARM::R_ARM_GOT_BREL12,         "GOT_BREL12"},
    { RELOC_ARM::R_ARM_GOTOFF12,           "GOTOFF12"},
    { RELOC_ARM::R_ARM_GOTRELAX,           "GOTRELAX"},
    { RELOC_ARM::R_ARM_GNU_VTENTRY,        "GNU_VTENTRY"},
    { RELOC_ARM::R_ARM_GNU_VTINHERIT,      "GNU_VTINHERIT"},
    { RELOC_ARM::R_ARM_THM_JUMP11,         "THM_JUMP11"},
    { RELOC_ARM::R_ARM_THM_JUMP8,          "THM_JUMP8"},
    { RELOC_ARM::R_ARM_TLS_GD32,           "TLS_GD32"},
    { RELOC_ARM::R_ARM_TLS_LDM32,          "TLS_LDM32"},
    { RELOC_ARM::R_ARM_TLS_LDO32,          "TLS_LDO32"},
    { RELOC_ARM::R_ARM_TLS_IE32,           "TLS_IE32"},
    { RELOC_ARM::R_ARM_TLS_LE32,           "TLS_LE32"},
    { RELOC_ARM::R_ARM_TLS_LDO12,          "TLS_LDO12"},
    { RELOC_ARM::R_ARM_TLS_LE12,           "TLS_LE12"},
    { RELOC_ARM::R_ARM_TLS_IE12GP,         "TLS_IE12GP"},
    { RELOC_ARM::R_ARM_PRIVATE_0,          "PRIVATE_0"},
    { RELOC_ARM::R_ARM_PRIVATE_1,          "PRIVATE_1"},
    { RELOC_ARM::R_ARM_PRIVATE_2,          "PRIVATE_2"},
    { RELOC_ARM::R_ARM_PRIVATE_3,          "PRIVATE_3"},
    { RELOC_ARM::R_ARM_PRIVATE_4,          "PRIVATE_4"},
    { RELOC_ARM::R_ARM_PRIVATE_5,          "PRIVATE_5"},
    { RELOC_ARM::R_ARM_PRIVATE_6,          "PRIVATE_6"},
    { RELOC_ARM::R_ARM_PRIVATE_7,          "PRIVATE_7"},
    { RELOC_ARM::R_ARM_PRIVATE_8,          "PRIVATE_8"},
    { RELOC_ARM::R_ARM_PRIVATE_9,          "PRIVATE_9"},
    { RELOC_ARM::R_ARM_PRIVATE_10,         "PRIVATE_10"},
    { RELOC_ARM::R_ARM_PRIVATE_11,         "PRIVATE_11"},
    { RELOC_ARM::R_ARM_PRIVATE_12,         "PRIVATE_12"},
    { RELOC_ARM::R_ARM_PRIVATE_13,         "PRIVATE_13"},
    { RELOC_ARM::R_ARM_PRIVATE_14,         "PRIVATE_14"},
    { RELOC_ARM::R_ARM_PRIVATE_15,         "PRIVATE_15"},
    { RELOC_ARM::R_ARM_ME_TOO,             "ME_TOO"},
    { RELOC_ARM::R_ARM_THM_TLS_DESCSEQ16,  "THM_TLS_DESCSEQ16"},
    { RELOC_ARM::R_ARM_THM_TLS_DESCSEQ32,  "THM_TLS_DESCSEQ32"},
    { RELOC_ARM::R_ARM_IRELATIVE,          "IRELATIVE"},
    { RELOC_ARM::R_ARM_RXPC25,             "RXPC25"},
    { RELOC_ARM::R_ARM_RSBREL32,           "RSBREL32"},
    { RELOC_ARM::R_ARM_THM_RPC22,          "THM_RPC22"},
    { RELOC_ARM::R_ARM_RREL32,             "RREL32"},
    { RELOC_ARM::R_ARM_RPC24,              "RPC24"},
    { RELOC_ARM::R_ARM_RBASE,              "RBASE"},
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(RELOC_AARCH64 e) {
  CONST_MAP(RELOC_AARCH64, const char*, 123) enumStrings {
    { RELOC_AARCH64::R_AARCH64_NONE,                         "NONE"},
    { RELOC_AARCH64::R_AARCH64_ABS64,                        "ABS64"},
    { RELOC_AARCH64::R_AARCH64_ABS32,                        "ABS32"},
    { RELOC_AARCH64::R_AARCH64_ABS16,                        "ABS16"},
    { RELOC_AARCH64::R_AARCH64_PREL64,                       "PREL64"},
    { RELOC_AARCH64::R_AARCH64_PREL32,                       "PREL32"},
    { RELOC_AARCH64::R_AARCH64_PREL16,                       "PREL16"},
    { RELOC_AARCH64::R_AARCH64_MOVW_UABS_G0,                 "MOVW_UABS_G0"},
    { RELOC_AARCH64::R_AARCH64_MOVW_UABS_G0_NC,              "MOVW_UABS_G0_NC"},
    { RELOC_AARCH64::R_AARCH64_MOVW_UABS_G1,                 "MOVW_UABS_G1"},
    { RELOC_AARCH64::R_AARCH64_MOVW_UABS_G1_NC,              "MOVW_UABS_G1_NC"},
    { RELOC_AARCH64::R_AARCH64_MOVW_UABS_G2,                 "MOVW_UABS_G2"},
    { RELOC_AARCH64::R_AARCH64_MOVW_UABS_G2_NC,              "MOVW_UABS_G2_NC"},
    { RELOC_AARCH64::R_AARCH64_MOVW_UABS_G3,                 "MOVW_UABS_G3"},
    { RELOC_AARCH64::R_AARCH64_MOVW_SABS_G0,                 "MOVW_SABS_G0"},
    { RELOC_AARCH64::R_AARCH64_MOVW_SABS_G1,                 "MOVW_SABS_G1"},
    { RELOC_AARCH64::R_AARCH64_MOVW_SABS_G2,                 "MOVW_SABS_G2"},
    { RELOC_AARCH64::R_AARCH64_LD_PREL_LO19,                 "LD_PREL_LO19"},
    { RELOC_AARCH64::R_AARCH64_ADR_PREL_LO21,                "ADR_PREL_LO21"},
    { RELOC_AARCH64::R_AARCH64_ADR_PREL_PG_HI21,             "ADR_PREL_PG_HI21"},
    { RELOC_AARCH64::R_AARCH64_ADR_PREL_PG_HI21_NC,          "ADR_PREL_PG_HI21_NC"},
    { RELOC_AARCH64::R_AARCH64_ADD_ABS_LO12_NC,              "ADD_ABS_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_LDST8_ABS_LO12_NC,            "LDST8_ABS_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_TSTBR14,                      "TSTBR14"},
    { RELOC_AARCH64::R_AARCH64_CONDBR19,                     "CONDBR19"},
    { RELOC_AARCH64::R_AARCH64_JUMP26,                       "JUMP26"},
    { RELOC_AARCH64::R_AARCH64_CALL26,                       "CALL26"},
    { RELOC_AARCH64::R_AARCH64_LDST16_ABS_LO12_NC,           "LDST16_ABS_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_LDST32_ABS_LO12_NC,           "LDST32_ABS_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_LDST64_ABS_LO12_NC,           "LDST64_ABS_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_MOVW_PREL_G0,                 "MOVW_PREL_G0"},
    { RELOC_AARCH64::R_AARCH64_MOVW_PREL_G0_NC,              "MOVW_PREL_G0_NC"},
    { RELOC_AARCH64::R_AARCH64_MOVW_PREL_G1,                 "MOVW_PREL_G1"},
    { RELOC_AARCH64::R_AARCH64_MOVW_PREL_G1_NC,              "MOVW_PREL_G1_NC"},
    { RELOC_AARCH64::R_AARCH64_MOVW_PREL_G2,                 "MOVW_PREL_G2"},
    { RELOC_AARCH64::R_AARCH64_MOVW_PREL_G2_NC,              "MOVW_PREL_G2_NC"},
    { RELOC_AARCH64::R_AARCH64_MOVW_PREL_G3,                 "MOVW_PREL_G3"},
    { RELOC_AARCH64::R_AARCH64_LDST128_ABS_LO12_NC,          "LDST128_ABS_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_MOVW_GOTOFF_G0,               "MOVW_GOTOFF_G0"},
    { RELOC_AARCH64::R_AARCH64_MOVW_GOTOFF_G0_NC,            "MOVW_GOTOFF_G0_NC"},
    { RELOC_AARCH64::R_AARCH64_MOVW_GOTOFF_G1,               "MOVW_GOTOFF_G1"},
    { RELOC_AARCH64::R_AARCH64_MOVW_GOTOFF_G1_NC,            "MOVW_GOTOFF_G1_NC"},
    { RELOC_AARCH64::R_AARCH64_MOVW_GOTOFF_G2,               "MOVW_GOTOFF_G2"},
    { RELOC_AARCH64::R_AARCH64_MOVW_GOTOFF_G2_NC,            "MOVW_GOTOFF_G2_NC"},
    { RELOC_AARCH64::R_AARCH64_MOVW_GOTOFF_G3,               "MOVW_GOTOFF_G3"},
    { RELOC_AARCH64::R_AARCH64_GOTREL64,                     "GOTREL64"},
    { RELOC_AARCH64::R_AARCH64_GOTREL32,                     "GOTREL32"},
    { RELOC_AARCH64::R_AARCH64_GOT_LD_PREL19,                "GOT_LD_PREL19"},
    { RELOC_AARCH64::R_AARCH64_LD64_GOTOFF_LO15,             "LD64_GOTOFF_LO15"},
    { RELOC_AARCH64::R_AARCH64_ADR_GOT_PAGE,                 "ADR_GOT_PAGE"},
    { RELOC_AARCH64::R_AARCH64_LD64_GOT_LO12_NC,             "LD64_GOT_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_LD64_GOTPAGE_LO15,            "LD64_GOTPAGE_LO15"},
    { RELOC_AARCH64::R_AARCH64_TLSGD_ADR_PREL21,             "TLSGD_ADR_PREL21"},
    { RELOC_AARCH64::R_AARCH64_TLSGD_ADR_PAGE21,             "TLSGD_ADR_PAGE21"},
    { RELOC_AARCH64::R_AARCH64_TLSGD_ADD_LO12_NC,            "TLSGD_ADD_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSGD_MOVW_G1,                "TLSGD_MOVW_G1"},
    { RELOC_AARCH64::R_AARCH64_TLSGD_MOVW_G0_NC,             "TLSGD_MOVW_G0_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_ADR_PREL21,             "TLSLD_ADR_PREL21"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_ADR_PAGE21,             "TLSLD_ADR_PAGE21"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_ADD_LO12_NC,            "TLSLD_ADD_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_MOVW_G1,                "TLSLD_MOVW_G1"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_MOVW_G0_NC,             "TLSLD_MOVW_G0_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_LD_PREL19,              "TLSLD_LD_PREL19"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_MOVW_DTPREL_G2,         "TLSLD_MOVW_DTPREL_G2"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_MOVW_DTPREL_G1,         "TLSLD_MOVW_DTPREL_G1"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC,      "TLSLD_MOVW_DTPREL_G1_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_MOVW_DTPREL_G0,         "TLSLD_MOVW_DTPREL_G0"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC,      "TLSLD_MOVW_DTPREL_G0_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_ADD_DTPREL_HI12,        "TLSLD_ADD_DTPREL_HI12"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_ADD_DTPREL_LO12,        "TLSLD_ADD_DTPREL_LO12"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC,     "TLSLD_ADD_DTPREL_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_LDST8_DTPREL_LO12,      "TLSLD_LDST8_DTPREL_LO12"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC,   "TLSLD_LDST8_DTPREL_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_LDST16_DTPREL_LO12,     "TLSLD_LDST16_DTPREL_LO12"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC,  "TLSLD_LDST16_DTPREL_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_LDST32_DTPREL_LO12,     "TLSLD_LDST32_DTPREL_LO12"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC,  "TLSLD_LDST32_DTPREL_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_LDST64_DTPREL_LO12,     "TLSLD_LDST64_DTPREL_LO12"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC,  "TLSLD_LDST64_DTPREL_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSIE_MOVW_GOTTPREL_G1,       "TLSIE_MOVW_GOTTPREL_G1"},
    { RELOC_AARCH64::R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC,    "TLSIE_MOVW_GOTTPREL_G0_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21,    "TLSIE_ADR_GOTTPREL_PAGE21"},
    { RELOC_AARCH64::R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC,  "TLSIE_LD64_GOTTPREL_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSIE_LD_GOTTPREL_PREL19,     "TLSIE_LD_GOTTPREL_PREL19"},
    { RELOC_AARCH64::R_AARCH64_TLSLE_MOVW_TPREL_G2,          "TLSLE_MOVW_TPREL_G2"},
    { RELOC_AARCH64::R_AARCH64_TLSLE_MOVW_TPREL_G1,          "TLSLE_MOVW_TPREL_G1"},
    { RELOC_AARCH64::R_AARCH64_TLSLE_MOVW_TPREL_G1_NC,       "TLSLE_MOVW_TPREL_G1_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSLE_MOVW_TPREL_G0,          "TLSLE_MOVW_TPREL_G0"},
    { RELOC_AARCH64::R_AARCH64_TLSLE_MOVW_TPREL_G0_NC,       "TLSLE_MOVW_TPREL_G0_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSLE_ADD_TPREL_HI12,         "TLSLE_ADD_TPREL_HI12"},
    { RELOC_AARCH64::R_AARCH64_TLSLE_ADD_TPREL_LO12,         "TLSLE_ADD_TPREL_LO12"},
    { RELOC_AARCH64::R_AARCH64_TLSLE_ADD_TPREL_LO12_NC,      "TLSLE_ADD_TPREL_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSLE_LDST8_TPREL_LO12,       "TLSLE_LDST8_TPREL_LO12"},
    { RELOC_AARCH64::R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC,    "TLSLE_LDST8_TPREL_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSLE_LDST16_TPREL_LO12,      "TLSLE_LDST16_TPREL_LO12"},
    { RELOC_AARCH64::R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC,   "TLSLE_LDST16_TPREL_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSLE_LDST32_TPREL_LO12,      "TLSLE_LDST32_TPREL_LO12"},
    { RELOC_AARCH64::R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC,   "TLSLE_LDST32_TPREL_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSLE_LDST64_TPREL_LO12,      "TLSLE_LDST64_TPREL_LO12"},
    { RELOC_AARCH64::R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC,   "TLSLE_LDST64_TPREL_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSDESC_LD_PREL19,            "TLSDESC_LD_PREL19"},
    { RELOC_AARCH64::R_AARCH64_TLSDESC_ADR_PREL21,           "TLSDESC_ADR_PREL21"},
    { RELOC_AARCH64::R_AARCH64_TLSDESC_ADR_PAGE21,           "TLSDESC_ADR_PAGE21"},
    { RELOC_AARCH64::R_AARCH64_TLSDESC_LD64_LO12_NC,         "TLSDESC_LD64_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSDESC_ADD_LO12_NC,          "TLSDESC_ADD_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSDESC_OFF_G1,               "TLSDESC_OFF_G1"},
    { RELOC_AARCH64::R_AARCH64_TLSDESC_OFF_G0_NC,            "TLSDESC_OFF_G0_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSDESC_LDR,                  "TLSDESC_LDR"},
    { RELOC_AARCH64::R_AARCH64_TLSDESC_ADD,                  "TLSDESC_ADD"},
    { RELOC_AARCH64::R_AARCH64_TLSDESC_CALL,                 "TLSDESC_CALL"},
    { RELOC_AARCH64::R_AARCH64_TLSLE_LDST128_TPREL_LO12,     "TLSLE_LDST128_TPREL_LO12"},
    { RELOC_AARCH64::R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC,  "TLSLE_LDST128_TPREL_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_LDST128_DTPREL_LO12,    "TLSLD_LDST128_DTPREL_LO12"},
    { RELOC_AARCH64::R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC, "TLSLD_LDST128_DTPREL_LO12_NC"},
    { RELOC_AARCH64::R_AARCH64_COPY,                         "COPY"},
    { RELOC_AARCH64::R_AARCH64_GLOB_DAT,                     "GLOB_DAT"},
    { RELOC_AARCH64::R_AARCH64_JUMP_SLOT,                    "JUMP_SLOT"},
    { RELOC_AARCH64::R_AARCH64_RELATIVE,                     "RELATIVE"},
    { RELOC_AARCH64::R_AARCH64_TLS_DTPREL64,                 "TLS_DTPREL64"},
    { RELOC_AARCH64::R_AARCH64_TLS_DTPMOD64,                 "TLS_DTPMOD64"},
    { RELOC_AARCH64::R_AARCH64_TLS_TPREL64,                  "TLS_TPREL64"},
    { RELOC_AARCH64::R_AARCH64_TLSDESC,                      "TLSDESC"},
    { RELOC_AARCH64::R_AARCH64_IRELATIVE,                    "IRELATIVE"},

  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(RELOC_i386 e) {
  CONST_MAP(RELOC_i386, const char*, 41) enumStrings {
    { RELOC_i386::R_386_NONE,          "NONE"},
    { RELOC_i386::R_386_32,            "R32"},
    { RELOC_i386::R_386_PC32,          "PC32"},
    { RELOC_i386::R_386_GOT32,         "GOT32"},
    { RELOC_i386::R_386_PLT32,         "PLT32"},
    { RELOC_i386::R_386_COPY,          "COPY"},
    { RELOC_i386::R_386_GLOB_DAT,      "GLOB_DAT"},
    { RELOC_i386::R_386_JUMP_SLOT,     "JUMP_SLOT"},
    { RELOC_i386::R_386_RELATIVE,      "RELATIVE"},
    { RELOC_i386::R_386_GOTOFF,        "GOTOFF"},
    { RELOC_i386::R_386_GOTPC,         "GOTPC"},
    { RELOC_i386::R_386_32PLT,         "R32PLT"},
    { RELOC_i386::R_386_TLS_TPOFF,     "TLS_TPOFF"},
    { RELOC_i386::R_386_TLS_IE,        "TLS_IE"},
    { RELOC_i386::R_386_TLS_GOTIE,     "TLS_GOTIE"},
    { RELOC_i386::R_386_TLS_LE,        "TLS_LE"},
    { RELOC_i386::R_386_TLS_GD,        "TLS_GD"},
    { RELOC_i386::R_386_TLS_LDM,       "TLS_LDM"},
    { RELOC_i386::R_386_16,            "R16"},
    { RELOC_i386::R_386_PC16,          "PC16"},
    { RELOC_i386::R_386_8,             "R8"},
    { RELOC_i386::R_386_PC8,           "PC8"},
    { RELOC_i386::R_386_TLS_GD_32,     "TLS_GD_32"},
    { RELOC_i386::R_386_TLS_GD_PUSH,   "TLS_GD_PUSH"},
    { RELOC_i386::R_386_TLS_GD_CALL,   "TLS_GD_CALL"},
    { RELOC_i386::R_386_TLS_GD_POP,    "TLS_GD_POP"},
    { RELOC_i386::R_386_TLS_LDM_32,    "TLS_LDM_32"},
    { RELOC_i386::R_386_TLS_LDM_PUSH,  "TLS_LDM_PUSH"},
    { RELOC_i386::R_386_TLS_LDM_CALL,  "TLS_LDM_CALL"},
    { RELOC_i386::R_386_TLS_LDM_POP,   "TLS_LDM_POP"},
    { RELOC_i386::R_386_TLS_LDO_32,    "TLS_LDO_32"},
    { RELOC_i386::R_386_TLS_IE_32,     "TLS_IE_32"},
    { RELOC_i386::R_386_TLS_LE_32,     "TLS_LE_32"},
    { RELOC_i386::R_386_TLS_DTPMOD32,  "TLS_DTPMOD32"},
    { RELOC_i386::R_386_TLS_DTPOFF32,  "TLS_DTPOFF32"},
    { RELOC_i386::R_386_TLS_TPOFF32,   "TLS_TPOFF32"},
    { RELOC_i386::R_386_TLS_GOTDESC,   "TLS_GOTDESC"},
    { RELOC_i386::R_386_TLS_DESC_CALL, "TLS_DESC_CALL"},
    { RELOC_i386::R_386_TLS_DESC,      "TLS_DESC"},
    { RELOC_i386::R_386_IRELATIVE,     "IRELATIVE"},
    { RELOC_i386::R_386_NUM,           "NUM"},
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(RELOC_POWERPC32 e) {
  CONST_MAP(RELOC_POWERPC32, const char*, 57) enumStrings {
  { RELOC_POWERPC32::R_PPC_NONE,              "NONE" },
  { RELOC_POWERPC32::R_PPC_ADDR32,            "ADDR32" },
  { RELOC_POWERPC32::R_PPC_ADDR24,            "ADDR24" },
  { RELOC_POWERPC32::R_PPC_ADDR16,            "ADDR16" },
  { RELOC_POWERPC32::R_PPC_ADDR16_LO,         "ADDR16_LO" },
  { RELOC_POWERPC32::R_PPC_ADDR16_HI,         "ADDR16_HI" },
  { RELOC_POWERPC32::R_PPC_ADDR16_HA,         "ADDR16_HA" },
  { RELOC_POWERPC32::R_PPC_ADDR14,            "ADDR14" },
  { RELOC_POWERPC32::R_PPC_ADDR14_BRTAKEN,    "ADDR14_BRTAKEN" },
  { RELOC_POWERPC32::R_PPC_ADDR14_BRNTAKEN,   "ADDR14_BRNTAKEN" },
  { RELOC_POWERPC32::R_PPC_REL24,             "REL24" },
  { RELOC_POWERPC32::R_PPC_REL14,             "REL14" },
  { RELOC_POWERPC32::R_PPC_REL14_BRTAKEN,     "REL14_BRTAKEN" },
  { RELOC_POWERPC32::R_PPC_REL14_BRNTAKEN,    "REL14_BRNTAKEN" },
  { RELOC_POWERPC32::R_PPC_GOT16,             "GOT16" },
  { RELOC_POWERPC32::R_PPC_GOT16_LO,          "GOT16_LO" },
  { RELOC_POWERPC32::R_PPC_GOT16_HI,          "GOT16_HI" },
  { RELOC_POWERPC32::R_PPC_GOT16_HA,          "GOT16_HA" },
  { RELOC_POWERPC32::R_PPC_PLTREL24,          "PLTREL24" },
  { RELOC_POWERPC32::R_PPC_JMP_SLOT,          "JMP_SLOT" },
  { RELOC_POWERPC32::R_PPC_RELATIVE,          "RELATIVE" },
  { RELOC_POWERPC32::R_PPC_LOCAL24PC,         "LOCAL24PC" },
  { RELOC_POWERPC32::R_PPC_REL32,             "REL32" },
  { RELOC_POWERPC32::R_PPC_TLS,               "TLS" },
  { RELOC_POWERPC32::R_PPC_DTPMOD32,          "DTPMOD32" },
  { RELOC_POWERPC32::R_PPC_TPREL16,           "TPREL16" },
  { RELOC_POWERPC32::R_PPC_TPREL16_LO,        "TPREL16_LO" },
  { RELOC_POWERPC32::R_PPC_TPREL16_HI,        "TPREL16_HI" },
  { RELOC_POWERPC32::R_PPC_TPREL16_HA,        "TPREL16_HA" },
  { RELOC_POWERPC32::R_PPC_TPREL32,           "TPREL32" },
  { RELOC_POWERPC32::R_PPC_DTPREL16,          "DTPREL16" },
  { RELOC_POWERPC32::R_PPC_DTPREL16_LO,       "DTPREL16_LO" },
  { RELOC_POWERPC32::R_PPC_DTPREL16_HI,       "DTPREL16_HI" },
  { RELOC_POWERPC32::R_PPC_DTPREL16_HA,       "DTPREL16_HA" },
  { RELOC_POWERPC32::R_PPC_DTPREL32,          "DTPREL32" },
  { RELOC_POWERPC32::R_PPC_GOT_TLSGD16,       "GOT_TLSGD16" },
  { RELOC_POWERPC32::R_PPC_GOT_TLSGD16_LO,    "GOT_TLSGD16_LO" },
  { RELOC_POWERPC32::R_PPC_GOT_TLSGD16_HI,    "GOT_TLSGD16_HI" },
  { RELOC_POWERPC32::R_PPC_GOT_TLSGD16_HA,    "GOT_TLSGD16_HA" },
  { RELOC_POWERPC32::R_PPC_GOT_TLSLD16,       "GOT_TLSLD16" },
  { RELOC_POWERPC32::R_PPC_GOT_TLSLD16_LO,    "GOT_TLSLD16_LO" },
  { RELOC_POWERPC32::R_PPC_GOT_TLSLD16_HI,    "GOT_TLSLD16_HI" },
  { RELOC_POWERPC32::R_PPC_GOT_TLSLD16_HA,    "GOT_TLSLD16_HA" },
  { RELOC_POWERPC32::R_PPC_GOT_TPREL16,       "GOT_TPREL16" },
  { RELOC_POWERPC32::R_PPC_GOT_TPREL16_LO,    "GOT_TPREL16_LO" },
  { RELOC_POWERPC32::R_PPC_GOT_TPREL16_HI,    "GOT_TPREL16_HI" },
  { RELOC_POWERPC32::R_PPC_GOT_TPREL16_HA,    "GOT_TPREL16_HA" },
  { RELOC_POWERPC32::R_PPC_GOT_DTPREL16,      "GOT_DTPREL16" },
  { RELOC_POWERPC32::R_PPC_GOT_DTPREL16_LO,   "GOT_DTPREL16_LO" },
  { RELOC_POWERPC32::R_PPC_GOT_DTPREL16_HI,   "GOT_DTPREL16_HI" },
  { RELOC_POWERPC32::R_PPC_GOT_DTPREL16_HA,   "GOT_DTPREL16_HA" },
  { RELOC_POWERPC32::R_PPC_TLSGD,             "TLSGD" },
  { RELOC_POWERPC32::R_PPC_TLSLD,             "TLSLD" },
  { RELOC_POWERPC32::R_PPC_REL16,             "REL16" },
  { RELOC_POWERPC32::R_PPC_REL16_LO,          "REL16_LO" },
  { RELOC_POWERPC32::R_PPC_REL16_HI,          "REL16_HI" },
  { RELOC_POWERPC32::R_PPC_REL16_HA,          "REL16_HA" },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(RELOC_POWERPC64 e) {
  CONST_MAP(RELOC_POWERPC64, const char*, 84) enumStrings {
  { RELOC_POWERPC64::R_PPC64_NONE,                "NONE" },
  { RELOC_POWERPC64::R_PPC64_ADDR32,              "ADDR32" },
  { RELOC_POWERPC64::R_PPC64_ADDR24,              "ADDR24" },
  { RELOC_POWERPC64::R_PPC64_ADDR16,              "ADDR16" },
  { RELOC_POWERPC64::R_PPC64_ADDR16_LO,           "ADDR16_LO" },
  { RELOC_POWERPC64::R_PPC64_ADDR16_HI,           "ADDR16_HI" },
  { RELOC_POWERPC64::R_PPC64_ADDR16_HA,           "ADDR16_HA" },
  { RELOC_POWERPC64::R_PPC64_ADDR14,              "ADDR14" },
  { RELOC_POWERPC64::R_PPC64_ADDR14_BRTAKEN,      "ADDR14_BRTAKEN" },
  { RELOC_POWERPC64::R_PPC64_ADDR14_BRNTAKEN,     "ADDR14_BRNTAKEN" },
  { RELOC_POWERPC64::R_PPC64_REL24,               "REL24" },
  { RELOC_POWERPC64::R_PPC64_REL14,               "REL14" },
  { RELOC_POWERPC64::R_PPC64_REL14_BRTAKEN,       "REL14_BRTAKEN" },
  { RELOC_POWERPC64::R_PPC64_REL14_BRNTAKEN,      "REL14_BRNTAKEN" },
  { RELOC_POWERPC64::R_PPC64_GOT16,               "GOT16" },
  { RELOC_POWERPC64::R_PPC64_GOT16_LO,            "GOT16_LO" },
  { RELOC_POWERPC64::R_PPC64_GOT16_HI,            "GOT16_HI" },
  { RELOC_POWERPC64::R_PPC64_GOT16_HA,            "GOT16_HA" },
  { RELOC_POWERPC64::R_PPC64_JMP_SLOT,            "JMP_SLOT" },
  { RELOC_POWERPC64::R_PPC64_RELATIVE,            "RELATIVE"},
  { RELOC_POWERPC64::R_PPC64_REL32,               "REL32" },
  { RELOC_POWERPC64::R_PPC64_ADDR64,              "ADDR64" },
  { RELOC_POWERPC64::R_PPC64_ADDR16_HIGHER,       "ADDR16_HIGHER" },
  { RELOC_POWERPC64::R_PPC64_ADDR16_HIGHERA,      "ADDR16_HIGHERA" },
  { RELOC_POWERPC64::R_PPC64_ADDR16_HIGHEST,      "ADDR16_HIGHEST" },
  { RELOC_POWERPC64::R_PPC64_ADDR16_HIGHESTA,     "ADDR16_HIGHESTA" },
  { RELOC_POWERPC64::R_PPC64_REL64,               "REL64" },
  { RELOC_POWERPC64::R_PPC64_TOC16,               "TOC16" },
  { RELOC_POWERPC64::R_PPC64_TOC16_LO,            "TOC16_LO" },
  { RELOC_POWERPC64::R_PPC64_TOC16_HI,            "TOC16_HI" },
  { RELOC_POWERPC64::R_PPC64_TOC16_HA,            "TOC16_HA" },
  { RELOC_POWERPC64::R_PPC64_TOC,                 "TOC" },
  { RELOC_POWERPC64::R_PPC64_ADDR16_DS,           "ADDR16_DS" },
  { RELOC_POWERPC64::R_PPC64_ADDR16_LO_DS,        "ADDR16_LO_DS" },
  { RELOC_POWERPC64::R_PPC64_GOT16_DS,            "GOT16_DS" },
  { RELOC_POWERPC64::R_PPC64_GOT16_LO_DS,         "GOT16_LO_DS" },
  { RELOC_POWERPC64::R_PPC64_TOC16_DS,            "TOC16_DS" },
  { RELOC_POWERPC64::R_PPC64_TOC16_LO_DS,         "TOC16_LO_DS" },
  { RELOC_POWERPC64::R_PPC64_TLS,                 "TLS" },
  { RELOC_POWERPC64::R_PPC64_DTPMOD64,            "DTPMOD64" },
  { RELOC_POWERPC64::R_PPC64_TPREL16,             "TPREL16" },
  { RELOC_POWERPC64::R_PPC64_TPREL16_LO,          "TPREL16_LO" },
  { RELOC_POWERPC64::R_PPC64_TPREL16_HI,          "TPREL16_HI" },
  { RELOC_POWERPC64::R_PPC64_TPREL16_HA,          "TPREL16_HA" },
  { RELOC_POWERPC64::R_PPC64_TPREL64,             "TPREL64" },
  { RELOC_POWERPC64::R_PPC64_DTPREL16,            "DTPREL16" },
  { RELOC_POWERPC64::R_PPC64_DTPREL16_LO,         "DTPREL16_LO" },
  { RELOC_POWERPC64::R_PPC64_DTPREL16_HI,         "DTPREL16_HI" },
  { RELOC_POWERPC64::R_PPC64_DTPREL16_HA,         "DTPREL16_HA" },
  { RELOC_POWERPC64::R_PPC64_DTPREL64,            "DTPREL64" },
  { RELOC_POWERPC64::R_PPC64_GOT_TLSGD16,         "GOT_TLSGD16" },
  { RELOC_POWERPC64::R_PPC64_GOT_TLSGD16_LO,      "GOT_TLSGD16_LO" },
  { RELOC_POWERPC64::R_PPC64_GOT_TLSGD16_HI,      "GOT_TLSGD16_HI" },
  { RELOC_POWERPC64::R_PPC64_GOT_TLSGD16_HA,      "GOT_TLSGD16_HA" },
  { RELOC_POWERPC64::R_PPC64_GOT_TLSLD16,         "GOT_TLSLD16" },
  { RELOC_POWERPC64::R_PPC64_GOT_TLSLD16_LO,      "GOT_TLSLD16_LO" },
  { RELOC_POWERPC64::R_PPC64_GOT_TLSLD16_HI,      "GOT_TLSLD16_HI" },
  { RELOC_POWERPC64::R_PPC64_GOT_TLSLD16_HA,      "GOT_TLSLD16_HA" },
  { RELOC_POWERPC64::R_PPC64_GOT_TPREL16_DS,      "GOT_TPREL16_DS" },
  { RELOC_POWERPC64::R_PPC64_GOT_TPREL16_LO_DS,   "GOT_TPREL16_LO_DS" },
  { RELOC_POWERPC64::R_PPC64_GOT_TPREL16_HI,      "GOT_TPREL16_HI" },
  { RELOC_POWERPC64::R_PPC64_GOT_TPREL16_HA,      "GOT_TPREL16_HA" },
  { RELOC_POWERPC64::R_PPC64_GOT_DTPREL16_DS,     "GOT_DTPREL16_DS" },
  { RELOC_POWERPC64::R_PPC64_GOT_DTPREL16_LO_DS,  "GOT_DTPREL16_LO_DS" },
  { RELOC_POWERPC64::R_PPC64_GOT_DTPREL16_HI,     "GOT_DTPREL16_HI" },
  { RELOC_POWERPC64::R_PPC64_GOT_DTPREL16_HA,     "GOT_DTPREL16_HA" },
  { RELOC_POWERPC64::R_PPC64_TPREL16_DS,          "TPREL16_DS" },
  { RELOC_POWERPC64::R_PPC64_TPREL16_LO_DS,       "TPREL16_LO_DS" },
  { RELOC_POWERPC64::R_PPC64_TPREL16_HIGHER,      "TPREL16_HIGHER" },
  { RELOC_POWERPC64::R_PPC64_TPREL16_HIGHERA,     "TPREL16_HIGHERA" },
  { RELOC_POWERPC64::R_PPC64_TPREL16_HIGHEST,     "TPREL16_HIGHEST" },
  { RELOC_POWERPC64::R_PPC64_TPREL16_HIGHESTA,    "TPREL16_HIGHESTA" },
  { RELOC_POWERPC64::R_PPC64_DTPREL16_DS,         "DTPREL16_DS" },
  { RELOC_POWERPC64::R_PPC64_DTPREL16_LO_DS,      "DTPREL16_LO_DS" },
  { RELOC_POWERPC64::R_PPC64_DTPREL16_HIGHER,     "DTPREL16_HIGHER" },
  { RELOC_POWERPC64::R_PPC64_DTPREL16_HIGHERA,    "DTPREL16_HIGHERA" },
  { RELOC_POWERPC64::R_PPC64_DTPREL16_HIGHEST,    "DTPREL16_HIGHEST" },
  { RELOC_POWERPC64::R_PPC64_DTPREL16_HIGHESTA,   "DTPREL16_HIGHESTA" },
  { RELOC_POWERPC64::R_PPC64_TLSGD,               "TLSGD" },
  { RELOC_POWERPC64::R_PPC64_TLSLD,               "TLSLD" },
  { RELOC_POWERPC64::R_PPC64_REL16,               "REL16" },
  { RELOC_POWERPC64::R_PPC64_REL16_LO,            "REL16_LO" },
  { RELOC_POWERPC64::R_PPC64_REL16_HI,            "REL16_HI" },
  { RELOC_POWERPC64::R_PPC64_REL16_HA,            "REL16_HA" },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(RELOC_MIPS e) {
  CONST_MAP(RELOC_MIPS, const char*, 112) enumStrings {
    {  RELOC_MIPS::R_MICROMIPS_26_S1,           "MIRCRO_MIPS_26_S1" },
    {  RELOC_MIPS::R_MICROMIPS_CALL16,          "MIRCRO_MIPS_CALL16" },
    {  RELOC_MIPS::R_MICROMIPS_CALL_HI16,       "MIRCRO_MIPS_CALL_HI16" },
    {  RELOC_MIPS::R_MICROMIPS_CALL_LO16,       "MIRCRO_MIPS_CALL_LO16" },
    {  RELOC_MIPS::R_MICROMIPS_GOT16,           "MIRCRO_MIPS_GOT16" },
    {  RELOC_MIPS::R_MICROMIPS_GOT_DISP,        "MIRCRO_MIPS_GOT_DISP" },
    {  RELOC_MIPS::R_MICROMIPS_GOT_HI16,        "MIRCRO_MIPS_GOT_HI16" },
    {  RELOC_MIPS::R_MICROMIPS_GOT_LO16,        "MIRCRO_MIPS_GOT_LO16" },
    {  RELOC_MIPS::R_MICROMIPS_GOT_OFST,        "MIRCRO_MIPS_GOT_OFST" },
    {  RELOC_MIPS::R_MICROMIPS_GOT_PAGE,        "MIRCRO_MIPS_GOT_PAGE" },
    {  RELOC_MIPS::R_MICROMIPS_GPREL16,         "MIRCRO_MIPS_GPREL16" },
    {  RELOC_MIPS::R_MICROMIPS_GPREL7_S2,       "MIRCRO_MIPS_GPREL7_S2" },
    {  RELOC_MIPS::R_MICROMIPS_HI0_LO16,        "MIRCRO_MIPS_HI0_LO16" },
    {  RELOC_MIPS::R_MICROMIPS_HI16,            "MIRCRO_MIPS_HI16" },
    {  RELOC_MIPS::R_MICROMIPS_HIGHER,          "MIRCRO_MIPS_HIGHER" },
    {  RELOC_MIPS::R_MICROMIPS_HIGHEST,         "MIRCRO_MIPS_HIGHEST" },
    {  RELOC_MIPS::R_MICROMIPS_JALR,            "MIRCRO_MIPS_JALR" },
    {  RELOC_MIPS::R_MICROMIPS_LITERAL,         "MIRCRO_MIPS_LITERAL" },
    {  RELOC_MIPS::R_MICROMIPS_LO16,            "MIRCRO_MIPS_LO16" },
    {  RELOC_MIPS::R_MICROMIPS_PC10_S1,         "MIRCRO_MIPS_PC10_S1" },
    {  RELOC_MIPS::R_MICROMIPS_PC16_S1,         "MIRCRO_MIPS_PC16_S1" },
    {  RELOC_MIPS::R_MICROMIPS_PC18_S3,         "MIRCRO_MIPS_PC18_S3" },
    {  RELOC_MIPS::R_MICROMIPS_PC19_S2,         "MIRCRO_MIPS_PC19_S2" },
    {  RELOC_MIPS::R_MICROMIPS_PC21_S2,         "MIRCRO_MIPS_PC21_S2" },
    {  RELOC_MIPS::R_MICROMIPS_PC23_S2,         "MIRCRO_MIPS_PC23_S2" },
    {  RELOC_MIPS::R_MICROMIPS_PC26_S2,         "MIRCRO_MIPS_PC26_S2" },
    {  RELOC_MIPS::R_MICROMIPS_PC7_S1,          "MIRCRO_MIPS_PC7_S1" },
    {  RELOC_MIPS::R_MICROMIPS_SCN_DISP,        "MIRCRO_MIPS_SCN_DISP" },
    {  RELOC_MIPS::R_MICROMIPS_SUB,             "MIRCRO_MIPS_SUB" },
    {  RELOC_MIPS::R_MICROMIPS_TLS_DTPREL_HI16, "MIRCRO_MIPS_TLS_DTPREL_HI16" },
    {  RELOC_MIPS::R_MICROMIPS_TLS_DTPREL_LO16, "MIRCRO_MIPS_TLS_DTPREL_LO16" },
    {  RELOC_MIPS::R_MICROMIPS_TLS_GD,          "MIRCRO_MIPS_TLS_GD" },
    {  RELOC_MIPS::R_MICROMIPS_TLS_GOTTPREL,    "MIRCRO_MIPS_TLS_GOTTPREL" },
    {  RELOC_MIPS::R_MICROMIPS_TLS_LDM,         "MIRCRO_MIPS_TLS_LDM" },
    {  RELOC_MIPS::R_MICROMIPS_TLS_TPREL_HI16,  "MIRCRO_MIPS_TLS_TPREL_HI16" },
    {  RELOC_MIPS::R_MICROMIPS_TLS_TPREL_LO16,  "MIRCRO_MIPS_TLS_TPREL_LO16" },
    {  RELOC_MIPS::R_MIPS_16,                   "MIPS16_16"},
    {  RELOC_MIPS::R_MIPS16_26,                 "MIPS16_26" },
    {  RELOC_MIPS::R_MIPS16_CALL16,             "MIPS16_CALL16" },
    {  RELOC_MIPS::R_MIPS16_GOT16,              "MIPS16_GOT16" },
    {  RELOC_MIPS::R_MIPS16_GPREL,              "MIPS16_GPREL" },
    {  RELOC_MIPS::R_MIPS16_HI16,               "MIPS16_HI16" },
    {  RELOC_MIPS::R_MIPS16_LO16,               "MIPS16_LO16" },
    {  RELOC_MIPS::R_MIPS16_TLS_DTPREL_HI16,    "MIPS16_TLS_DTPREL_HI16" },
    {  RELOC_MIPS::R_MIPS16_TLS_DTPREL_LO16,    "MIPS16_TLS_DTPREL_LO16" },
    {  RELOC_MIPS::R_MIPS16_TLS_GD,             "MIPS16_TLS_GD" },
    {  RELOC_MIPS::R_MIPS16_TLS_GOTTPREL,       "MIPS16_TLS_GOTTPREL" },
    {  RELOC_MIPS::R_MIPS16_TLS_LDM,            "MIPS16_TLS_LDM" },
    {  RELOC_MIPS::R_MIPS16_TLS_TPREL_HI16,     "MIPS16_TLS_TPREL_HI16" },
    {  RELOC_MIPS::R_MIPS16_TLS_TPREL_LO16,     "MIPS16_TLS_TPREL_LO16" },
    {  RELOC_MIPS::R_MIPS_26,                   "MIPS_26" },
    {  RELOC_MIPS::R_MIPS_32,                   "MIPS_32" },
    {  RELOC_MIPS::R_MIPS_64,                   "MIPS_64" },
    {  RELOC_MIPS::R_MIPS_ADD_IMMEDIATE,        "MIPS_ADD_IMMEDIATE" },
    {  RELOC_MIPS::R_MIPS_CALL16,               "MIPS_CALL16" },
    {  RELOC_MIPS::R_MIPS_CALL_HI16,            "MIPS_CALL_HI16" },
    {  RELOC_MIPS::R_MIPS_CALL_LO16,            "MIPS_CALL_LO16" },
    {  RELOC_MIPS::R_MIPS_COPY,                 "MIPS_COPY" },
    {  RELOC_MIPS::R_MIPS_DELETE,               "MIPS_DELETE" },
    {  RELOC_MIPS::R_MIPS_EH,                   "MIPS_EH" },
    {  RELOC_MIPS::R_MIPS_GLOB_DAT,             "MIPS_GLOB_DAT" },
    {  RELOC_MIPS::R_MIPS_GOT16,                "MIPS_GOT16" },
    {  RELOC_MIPS::R_MIPS_GOT_DISP,             "MIPS_GOT_DISP" },
    {  RELOC_MIPS::R_MIPS_GOT_HI16,             "MIPS_GOT_HI16" },
    {  RELOC_MIPS::R_MIPS_GOT_LO16,             "MIPS_GOT_LO16" },
    {  RELOC_MIPS::R_MIPS_GOT_OFST,             "MIPS_GOT_OFST" },
    {  RELOC_MIPS::R_MIPS_GOT_PAGE,             "MIPS_GOT_PAGE" },
    {  RELOC_MIPS::R_MIPS_GPREL16,              "MIPS_GPREL16" },
    {  RELOC_MIPS::R_MIPS_GPREL32,              "MIPS_GPREL32" },
    {  RELOC_MIPS::R_MIPS_HI16,                 "MIPS_HI16" },
    {  RELOC_MIPS::R_MIPS_HIGHER,               "MIPS_HIGHER" },
    {  RELOC_MIPS::R_MIPS_HIGHEST,              "MIPS_HIGHEST" },
    {  RELOC_MIPS::R_MIPS_INSERT_A,             "MIPS_INSERT_A" },
    {  RELOC_MIPS::R_MIPS_INSERT_B,             "MIPS_INSERT_B" },
    {  RELOC_MIPS::R_MIPS_JALR,                 "MIPS_JALR" },
    {  RELOC_MIPS::R_MIPS_JUMP_SLOT,            "MIPS_JUMP_SLOT" },
    {  RELOC_MIPS::R_MIPS_LITERAL,              "MIPS_LITERAL" },
    {  RELOC_MIPS::R_MIPS_LO16,                 "MIPS_LO16" },
    {  RELOC_MIPS::R_MIPS_NONE,                 "MIPS_NONE"},
    {  RELOC_MIPS::R_MIPS_NUM,                  "MIPS_NUM" },
    {  RELOC_MIPS::R_MIPS_PC16,                 "MIPS_PC16" },
    {  RELOC_MIPS::R_MIPS_PC18_S3,              "MIPS_PC18_S3" },
    {  RELOC_MIPS::R_MIPS_PC19_S2,              "MIPS_PC19_S2" },
    {  RELOC_MIPS::R_MIPS_PC21_S2,              "MIPS_PC21_S2" },
    {  RELOC_MIPS::R_MIPS_PC26_S2,              "MIPS_PC26_S2" },
    {  RELOC_MIPS::R_MIPS_PC32,                 "MIPS_PC32" },
    {  RELOC_MIPS::R_MIPS_PCHI16,               "MIPS_PCHI16" },
    {  RELOC_MIPS::R_MIPS_PCLO16,               "MIPS_PCLO16" },
    {  RELOC_MIPS::R_MIPS_PJUMP,                "MIPS_PJUMP" },
    {  RELOC_MIPS::R_MIPS_REL16,                "MIPS_REL16" },
    {  RELOC_MIPS::R_MIPS_REL32,                "MIPS_REL32" },
    {  RELOC_MIPS::R_MIPS_RELGOT,               "MIPS_RELGOT" },
    {  RELOC_MIPS::R_MIPS_SCN_DISP,             "MIPS_SCN_DISP" },
    {  RELOC_MIPS::R_MIPS_SHIFT5,               "MIPS_SHIFT5" },
    {  RELOC_MIPS::R_MIPS_SHIFT6,               "MIPS_SHIFT6" },
    {  RELOC_MIPS::R_MIPS_SUB,                  "MIPS_SUB" },
    {  RELOC_MIPS::R_MIPS_TLS_DTPMOD32,         "MIPS_TLS_DTPMOD32" },
    {  RELOC_MIPS::R_MIPS_TLS_DTPMOD64,         "MIPS_TLS_DTPMOD64" },
    {  RELOC_MIPS::R_MIPS_TLS_DTPREL32,         "MIPS_TLS_DTPREL32" },
    {  RELOC_MIPS::R_MIPS_TLS_DTPREL64,         "MIPS_TLS_DTPREL64" },
    {  RELOC_MIPS::R_MIPS_TLS_DTPREL_HI16,      "MIPS_TLS_DTPREL_HI16" },
    {  RELOC_MIPS::R_MIPS_TLS_DTPREL_LO16,      "MIPS_TLS_DTPREL_LO16" },
    {  RELOC_MIPS::R_MIPS_TLS_GD,               "MIPS_TLS_GD" },
    {  RELOC_MIPS::R_MIPS_TLS_GOTTPREL,         "MIPS_TLS_GOTTPREL" },
    {  RELOC_MIPS::R_MIPS_TLS_LDM,              "MIPS_TLS_LDM" },
    {  RELOC_MIPS::R_MIPS_TLS_TPREL32,          "MIPS_TLS_TPREL32" },
    {  RELOC_MIPS::R_MIPS_TLS_TPREL64,          "MIPS_TLS_TPREL64" },
    {  RELOC_MIPS::R_MIPS_TLS_TPREL_HI16,       "MIPS_TLS_TPREL_HI16" },
    {  RELOC_MIPS::R_MIPS_TLS_TPREL_LO16,       "MIPS_TLS_TPREL_LO16" },
    {  RELOC_MIPS::R_MIPS_UNUSED1,              "MIPS_UNUSED1" },
    {  RELOC_MIPS::R_MIPS_UNUSED2,              "MIPS_UNUSED2" },
    {  RELOC_MIPS::R_MIPS_UNUSED3,              "MIPS_UNUSED3" },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(ELF_CLASS e) {
  CONST_MAP(ELF_CLASS, const char*, 3) enumStrings {
    { ELF_CLASS::ELFCLASSNONE, "NONE"},
    { ELF_CLASS::ELFCLASS32,   "CLASS32"},
    { ELF_CLASS::ELFCLASS64,   "CLASS64"},
  };

  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(ELF_DATA e) {
  CONST_MAP(ELF_DATA, const char*, 3) enumStrings {
    { ELF_DATA::ELFDATANONE, "NONE"},
    { ELF_DATA::ELFDATA2LSB, "LSB"},
    { ELF_DATA::ELFDATA2MSB, "MSB"},
  };

  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(OS_ABI e) {
  CONST_MAP(OS_ABI, const char*, 23) enumStrings {
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

  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(DYNSYM_COUNT_METHODS e) {
  CONST_MAP(DYNSYM_COUNT_METHODS, const char*, 4) enumStrings {
    { DYNSYM_COUNT_METHODS::COUNT_AUTO,        "AUTO"},
    { DYNSYM_COUNT_METHODS::COUNT_SECTION,     "SECTION"},
    { DYNSYM_COUNT_METHODS::COUNT_HASH,        "HASH"},
    { DYNSYM_COUNT_METHODS::COUNT_RELOCATIONS, "RELOCATIONS"},
  };

  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(NOTE_TYPES e) {
  CONST_MAP(NOTE_TYPES, const char*, 7) enumStrings {
    { NOTE_TYPES::NT_UNKNOWN,          "UNKNOWN"},
    { NOTE_TYPES::NT_GNU_ABI_TAG,      "ABI_TAG"},
    { NOTE_TYPES::NT_GNU_HWCAP,        "HWCAP"},
    { NOTE_TYPES::NT_GNU_BUILD_ID,     "BUILD_ID"},
    { NOTE_TYPES::NT_GNU_GOLD_VERSION, "GOLD_VERSION"},
    { NOTE_TYPES::NT_GNU_PROPERTY_TYPE_0, "PROPERTY_TYPE_0"},
    { NOTE_TYPES::NT_CRASHPAD,         "CRASHPAD"},
  };

  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(NOTE_TYPES_CORE e) {
  CONST_MAP(NOTE_TYPES_CORE, const char*, 17) enumStrings {
    { NOTE_TYPES_CORE::NT_CORE_UNKNOWN,     "UNKNOWN"},
    { NOTE_TYPES_CORE::NT_PRSTATUS,         "PRSTATUS"},
    { NOTE_TYPES_CORE::NT_PRFPREG,          "PRFPREG"},
    { NOTE_TYPES_CORE::NT_PRPSINFO,         "PRPSINFO"},
    { NOTE_TYPES_CORE::NT_TASKSTRUCT,       "TASKSTRUCT"},
    { NOTE_TYPES_CORE::NT_AUXV,             "AUXV"},
    { NOTE_TYPES_CORE::NT_SIGINFO,          "SIGINFO"},
    { NOTE_TYPES_CORE::NT_FILE,             "FILE"},

    { NOTE_TYPES_CORE::NT_ARM_VFP,          "ARM_VFP"},
    { NOTE_TYPES_CORE::NT_ARM_TLS,          "ARM_TLS"},
    { NOTE_TYPES_CORE::NT_ARM_HW_BREAK,     "ARM_HW_BREAK"},
    { NOTE_TYPES_CORE::NT_ARM_HW_WATCH,     "ARM_HW_WATCH"},
    { NOTE_TYPES_CORE::NT_ARM_SYSTEM_CALL,  "ARM_SYSTEM_CALL"},
    { NOTE_TYPES_CORE::NT_ARM_SVE,          "ARM_SVE"},

    { NOTE_TYPES_CORE::NT_386_TLS,          "I386_TLS"},
    { NOTE_TYPES_CORE::NT_386_IOPERM,       "I386_IOPERM"},
    { NOTE_TYPES_CORE::NT_386_XSTATE,       "I386_XSTATE"},
  };

  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNKNOWN" : it->second;
}


const char* to_string(NOTE_ABIS e) {
  CONST_MAP(NOTE_ABIS, const char*, 7) enumStrings {
    { NOTE_ABIS::ELF_NOTE_UNKNOWN,     "UNKNOWN"},
    { NOTE_ABIS::ELF_NOTE_OS_LINUX,    "LINUX"},
    { NOTE_ABIS::ELF_NOTE_OS_GNU,      "GNU"},
    { NOTE_ABIS::ELF_NOTE_OS_SOLARIS2, "SOLARIS2"},
    { NOTE_ABIS::ELF_NOTE_OS_FREEBSD,  "FREEBSD"},
    { NOTE_ABIS::ELF_NOTE_OS_NETBSD,   "NETBSD"},
    { NOTE_ABIS::ELF_NOTE_OS_SYLLABLE, "SYLLABLE"},
  };

  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(RELOCATION_PURPOSES e) {
  CONST_MAP(RELOCATION_PURPOSES, const char*, 4) enumStrings {
    { RELOCATION_PURPOSES::RELOC_PURPOSE_NONE,    "NONE"},
    { RELOCATION_PURPOSES::RELOC_PURPOSE_PLTGOT,  "PLTGOT"},
    { RELOCATION_PURPOSES::RELOC_PURPOSE_DYNAMIC, "DYNAMIC"},
    { RELOCATION_PURPOSES::RELOC_PURPOSE_OBJECT,  "OBJECT"},
  };

  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(PPC64_EFLAGS e) {
  CONST_MAP(PPC64_EFLAGS, const char*, 1) enumStrings {
    { PPC64_EFLAGS::EF_PPC64_ABI, "ABI"},
  };

  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(ARM_EFLAGS e) {
  CONST_MAP(ARM_EFLAGS, const char*, 8) enumStrings {
    { ARM_EFLAGS::EF_ARM_SOFT_FLOAT,   "SOFT_FLOAT" },
    { ARM_EFLAGS::EF_ARM_VFP_FLOAT,    "VFP_FLOAT"  },
    { ARM_EFLAGS::EF_ARM_EABI_UNKNOWN, "UNKNOWN"    },
    { ARM_EFLAGS::EF_ARM_EABI_VER1,    "EABI_VER1"  },
    { ARM_EFLAGS::EF_ARM_EABI_VER2,    "EABI_VER2"  },
    { ARM_EFLAGS::EF_ARM_EABI_VER3,    "EABI_VER3"  },
    { ARM_EFLAGS::EF_ARM_EABI_VER4,    "EABI_VER4"  },
    { ARM_EFLAGS::EF_ARM_EABI_VER5,    "EABI_VER5" },
  };

  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(MIPS_EFLAGS e) {
  CONST_MAP(MIPS_EFLAGS, const char*, 43) enumStrings {
    { MIPS_EFLAGS::EF_MIPS_NOREORDER,     "NOREORDER"     },
    { MIPS_EFLAGS::EF_MIPS_PIC,           "PIC"           },
    { MIPS_EFLAGS::EF_MIPS_CPIC,          "CPIC"          },
    { MIPS_EFLAGS::EF_MIPS_ABI2,          "ABI2"          },
    { MIPS_EFLAGS::EF_MIPS_32BITMODE,     "_32BITMODE"    },
    { MIPS_EFLAGS::EF_MIPS_FP64,          "FP64"          },
    { MIPS_EFLAGS::EF_MIPS_NAN2008,       "NAN2008"       },

    { MIPS_EFLAGS::EF_MIPS_ABI_O32,       "ABI_O32"       },
    { MIPS_EFLAGS::EF_MIPS_ABI_O64,       "ABI_O64"       },
    { MIPS_EFLAGS::EF_MIPS_ABI_EABI32,    "ABI_EABI32"    },
    { MIPS_EFLAGS::EF_MIPS_ABI_EABI64,    "ABI_EABI64"    },

    { MIPS_EFLAGS::EF_MIPS_MACH_3900,     "MACH_3900"     },
    { MIPS_EFLAGS::EF_MIPS_MACH_4010,     "MACH_4010"     },
    { MIPS_EFLAGS::EF_MIPS_MACH_4100,     "MACH_4100"     },
    { MIPS_EFLAGS::EF_MIPS_MACH_4650,     "MACH_4650"     },
    { MIPS_EFLAGS::EF_MIPS_MACH_4120,     "MACH_4120"     },
    { MIPS_EFLAGS::EF_MIPS_MACH_4111,     "MACH_4111"     },
    { MIPS_EFLAGS::EF_MIPS_MACH_SB1,      "MACH_SB1"      },
    { MIPS_EFLAGS::EF_MIPS_MACH_OCTEON,   "MACH_OCTEON"   },
    { MIPS_EFLAGS::EF_MIPS_MACH_XLR,      "MACH_XLR"      },
    { MIPS_EFLAGS::EF_MIPS_MACH_OCTEON2,  "MACH_OCTEON2"  },
    { MIPS_EFLAGS::EF_MIPS_MACH_OCTEON3,  "MACH_OCTEON3"  },
    { MIPS_EFLAGS::EF_MIPS_MACH_5400,     "MACH_5400"     },
    { MIPS_EFLAGS::EF_MIPS_MACH_5900,     "MACH_5900"     },
    { MIPS_EFLAGS::EF_MIPS_MACH_5500,     "MACH_5500"     },
    { MIPS_EFLAGS::EF_MIPS_MACH_9000,     "MACH_9000"     },
    { MIPS_EFLAGS::EF_MIPS_MACH_LS2E,     "MACH_LS2E"     },
    { MIPS_EFLAGS::EF_MIPS_MACH_LS2F,     "MACH_LS2F"     },
    { MIPS_EFLAGS::EF_MIPS_MACH_LS3A,     "MACH_LS3A"     },

    { MIPS_EFLAGS::EF_MIPS_MICROMIPS,     "MICROMIPS"     },
    { MIPS_EFLAGS::EF_MIPS_ARCH_ASE_M16,  "ARCH_ASE_M16"  },
    { MIPS_EFLAGS::EF_MIPS_ARCH_ASE_MDMX, "ARCH_ASE_MDMX" },

    { MIPS_EFLAGS::EF_MIPS_ARCH_1,        "ARCH_1"        },
    { MIPS_EFLAGS::EF_MIPS_ARCH_2,        "ARCH_2"        },
    { MIPS_EFLAGS::EF_MIPS_ARCH_3,        "ARCH_3"        },
    { MIPS_EFLAGS::EF_MIPS_ARCH_4,        "ARCH_4"        },
    { MIPS_EFLAGS::EF_MIPS_ARCH_5,        "ARCH_5"        },
    { MIPS_EFLAGS::EF_MIPS_ARCH_32,       "ARCH_32"       },
    { MIPS_EFLAGS::EF_MIPS_ARCH_64,       "ARCH_64"       },
    { MIPS_EFLAGS::EF_MIPS_ARCH_32R2,     "ARCH_32R2"     },
    { MIPS_EFLAGS::EF_MIPS_ARCH_64R2,     "ARCH_64R2"     },
    { MIPS_EFLAGS::EF_MIPS_ARCH_32R6,     "ARCH_32R6"     },
    { MIPS_EFLAGS::EF_MIPS_ARCH_64R6,     "ARCH_64R6"     },
  };

  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(HEXAGON_EFLAGS e) {
  CONST_MAP(HEXAGON_EFLAGS, const char*, 9) enumStrings {
    { HEXAGON_EFLAGS::EF_HEXAGON_MACH_V2,   "MACH_V2"  },
    { HEXAGON_EFLAGS::EF_HEXAGON_MACH_V3,   "MACH_V3"  },
    { HEXAGON_EFLAGS::EF_HEXAGON_MACH_V4,   "MACH_V4"  },
    { HEXAGON_EFLAGS::EF_HEXAGON_MACH_V5,   "MACH_V5"  },

    { HEXAGON_EFLAGS::EF_HEXAGON_ISA_MACH,  "ISA_MACH" },

    { HEXAGON_EFLAGS::EF_HEXAGON_ISA_V2,    "ISA_V2"   },
    { HEXAGON_EFLAGS::EF_HEXAGON_ISA_V3,    "ISA_V3"   },
    { HEXAGON_EFLAGS::EF_HEXAGON_ISA_V4,    "ISA_V4"   },
    { HEXAGON_EFLAGS::EF_HEXAGON_ISA_V5,    "ISA_V5"   },
  };

  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(IDENTITY e) {
  CONST_MAP(IDENTITY, const char*, 11) enumStrings {
    { IDENTITY::EI_MAG0,       "MAG0"       },
    { IDENTITY::EI_MAG1,       "MAG1"       },
    { IDENTITY::EI_MAG2,       "MAG2"       },
    { IDENTITY::EI_MAG3,       "MAG3"       },
    { IDENTITY::EI_CLASS,      "CLASS"      },
    { IDENTITY::EI_DATA,       "DATA"       },
    { IDENTITY::EI_VERSION,    "VERSION"    },
    { IDENTITY::EI_OSABI,      "OSABI"      },
    { IDENTITY::EI_ABIVERSION, "ABIVERSION" },
    { IDENTITY::EI_PAD,        "PAD"        },
    { IDENTITY::EI_NIDENT,     "NIDENT"     },
  };

  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(SYMBOL_SECTION_INDEX e) {
  CONST_MAP(SYMBOL_SECTION_INDEX, const char*, 10) enumStrings {
    { SYMBOL_SECTION_INDEX::SHN_UNDEF,     "UNDEF"     },
    { SYMBOL_SECTION_INDEX::SHN_LORESERVE, "LORESERVE" },
    { SYMBOL_SECTION_INDEX::SHN_LOPROC,    "LOPROC"    },
    { SYMBOL_SECTION_INDEX::SHN_HIPROC,    "HIPROC"    },
    { SYMBOL_SECTION_INDEX::SHN_LOOS,      "LOOS"      },
    { SYMBOL_SECTION_INDEX::SHN_HIOS,      "HIOS"      },
    { SYMBOL_SECTION_INDEX::SHN_ABS,       "ABS"       },
    { SYMBOL_SECTION_INDEX::SHN_COMMON,    "COMMON"    },
    { SYMBOL_SECTION_INDEX::SHN_XINDEX,    "XINDEX"    },
    { SYMBOL_SECTION_INDEX::SHN_HIRESERVE, "HIRESERVE" },
  };

  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(DYNAMIC_FLAGS e) {
  CONST_MAP(DYNAMIC_FLAGS, const char*, 5) enum_strings {
    { DYNAMIC_FLAGS::DF_ORIGIN,     "ORIGIN"         },
    { DYNAMIC_FLAGS::DF_SYMBOLIC,   "SYMBOLIC"       },
    { DYNAMIC_FLAGS::DF_TEXTREL,    "TEXTREL"        },
    { DYNAMIC_FLAGS::DF_BIND_NOW,   "BIND_NOW"       },
    { DYNAMIC_FLAGS::DF_STATIC_TLS, "STATIC_TLS"     },
  };

  const auto it = enum_strings.find(e);
  return it == enum_strings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(DYNAMIC_FLAGS_1 e) {
  CONST_MAP(DYNAMIC_FLAGS_1, const char*, 27) enum_strings_flags1 {
    { DYNAMIC_FLAGS_1::DF_1_NOW,        "NOW"        },
    { DYNAMIC_FLAGS_1::DF_1_GLOBAL,     "GLOBAL"     },
    { DYNAMIC_FLAGS_1::DF_1_GROUP,      "GROUP"      },
    { DYNAMIC_FLAGS_1::DF_1_NODELETE,   "NODELETE"   },
    { DYNAMIC_FLAGS_1::DF_1_LOADFLTR,   "LOADFLTR"   },
    { DYNAMIC_FLAGS_1::DF_1_INITFIRST,  "INITFIRST"  },
    { DYNAMIC_FLAGS_1::DF_1_NOOPEN,     "NOOPEN"     },
    { DYNAMIC_FLAGS_1::DF_1_ORIGIN,     "ORIGIN"     },
    { DYNAMIC_FLAGS_1::DF_1_DIRECT,     "DIRECT"     },
    { DYNAMIC_FLAGS_1::DF_1_TRANS,      "TRANS"      },
    { DYNAMIC_FLAGS_1::DF_1_INTERPOSE,  "INTERPOSE"  },
    { DYNAMIC_FLAGS_1::DF_1_NODEFLIB,   "NODEFLIB"   },
    { DYNAMIC_FLAGS_1::DF_1_NODUMP,     "NODUMP"     },
    { DYNAMIC_FLAGS_1::DF_1_CONFALT,    "CONFALT"    },
    { DYNAMIC_FLAGS_1::DF_1_ENDFILTEE,  "ENDFILTEE"  },
    { DYNAMIC_FLAGS_1::DF_1_DISPRELDNE, "DISPRELDNE" },
    { DYNAMIC_FLAGS_1::DF_1_DISPRELPND, "DISPRELPND" },
    { DYNAMIC_FLAGS_1::DF_1_NODIRECT,   "NODIRECT"   },
    { DYNAMIC_FLAGS_1::DF_1_IGNMULDEF,  "IGNMULDEF"  },
    { DYNAMIC_FLAGS_1::DF_1_NOKSYMS,    "NOKSYMS"    },
    { DYNAMIC_FLAGS_1::DF_1_NOHDR,      "NOHDR"      },
    { DYNAMIC_FLAGS_1::DF_1_EDITED,     "EDITED"     },
    { DYNAMIC_FLAGS_1::DF_1_NORELOC,    "NORELOC"    },
    { DYNAMIC_FLAGS_1::DF_1_SYMINTPOSE, "SYMINTPOSE" },
    { DYNAMIC_FLAGS_1::DF_1_GLOBAUDIT,  "GLOBAUDIT"  },
    { DYNAMIC_FLAGS_1::DF_1_SINGLETON,  "SINGLETON"  },
    { DYNAMIC_FLAGS_1::DF_1_PIE,        "PIE"  },
  };

  const auto it = enum_strings_flags1.find(e);
  return it == enum_strings_flags1.end() ? "UNDEFINED" : it->second;
}

const char* to_string(ELF_SEGMENT_FLAGS e) {
  CONST_MAP(ELF_SEGMENT_FLAGS, const char*, 4) enum_strings {
    { ELF_SEGMENT_FLAGS::PF_NONE, "NONE" },
    { ELF_SEGMENT_FLAGS::PF_X,    "X" },
    { ELF_SEGMENT_FLAGS::PF_W,    "W" },
    { ELF_SEGMENT_FLAGS::PF_R,    "R" },
  };

  const auto it = enum_strings.find(e);
  return it == enum_strings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(AUX_TYPE e) {
  CONST_MAP(AUX_TYPE, const char*, 32) enum_strings {
    { AUX_TYPE::AT_NULL, "NULL" },
    { AUX_TYPE::AT_IGNORE, "IGNORE" },
    { AUX_TYPE::AT_EXECFD, "EXECFD" },
    { AUX_TYPE::AT_PHDR, "PHDR" },
    { AUX_TYPE::AT_PHENT, "PHENT" },
    { AUX_TYPE::AT_PHNUM, "PHNUM" },
    { AUX_TYPE::AT_PAGESZ, "PAGESZ" },
    { AUX_TYPE::AT_BASE, "BASE" },
    { AUX_TYPE::AT_FLAGS, "FLAGS" },
    { AUX_TYPE::AT_ENTRY, "ENTRY" },
    { AUX_TYPE::AT_NOTELF, "NOTELF" },
    { AUX_TYPE::AT_UID, "UID" },
    { AUX_TYPE::AT_EUID, "EUID" },
    { AUX_TYPE::AT_GID, "GID" },
    { AUX_TYPE::AT_EGID, "EGID" },
    { AUX_TYPE::AT_CLKTCK, "CKLTCK" },
    { AUX_TYPE::AT_PLATFORM, "PLATFORM" },
    { AUX_TYPE::AT_HWCAP, "HWCAP" },
    { AUX_TYPE::AT_HWCAP2, "HWCAP2" },
    { AUX_TYPE::AT_FPUCW, "FPUCW" },
    { AUX_TYPE::AT_DCACHEBSIZE, "DCACHEBSIZE" },
    { AUX_TYPE::AT_ICACHEBSIZE, "ICACHEBSIZE" },
    { AUX_TYPE::AT_UCACHEBSIZE, "UCACHEBSIZE" },
    { AUX_TYPE::AT_IGNOREPPC, "IGNOREPPC" },
    { AUX_TYPE::AT_SECURE, "SECURE" },
    { AUX_TYPE::AT_BASE_PLATFORM, "BASE_PLATFORM" },
    { AUX_TYPE::AT_RANDOM, "RANDOM" },
    { AUX_TYPE::AT_EXECFN, "EXECFN" },
    { AUX_TYPE::AT_SYSINFO, "SYSINFO" },
    { AUX_TYPE::AT_SYSINFO_EHDR, "SYSINFO_EHDR" },
    { AUX_TYPE::AT_L1I_CACHESHAPE, "L1I_CACHESHAPE" },
    { AUX_TYPE::AT_L1D_CACHESHAPE, "L1D_CACHESHAPE" },
  };

  const auto it = enum_strings.find(e);
  return it == enum_strings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(ELF_SYMBOL_VISIBILITY e) {
  CONST_MAP(ELF_SYMBOL_VISIBILITY, const char*, 4) enum_strings {
    { ELF_SYMBOL_VISIBILITY::STV_DEFAULT,   "DEFAULT"   },
    { ELF_SYMBOL_VISIBILITY::STV_HIDDEN,    "HIDDEN"    },
    { ELF_SYMBOL_VISIBILITY::STV_INTERNAL,  "INTERNAL"  },
    { ELF_SYMBOL_VISIBILITY::STV_PROTECTED, "PROTECTED" },
  };

  const auto it = enum_strings.find(e);
  return it == enum_strings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(CorePrStatus::REGISTERS e) {
  CONST_MAP(CorePrStatus::REGISTERS, const char*, 90) enum_strings {
    { CorePrStatus::REGISTERS::UNKNOWN,     "UNKNOWN"   },

    // X86
    // ===
    { CorePrStatus::REGISTERS::X86_EBX,     "X86_EBX"    },
    { CorePrStatus::REGISTERS::X86_ECX,     "X86_ECX"    },
    { CorePrStatus::REGISTERS::X86_EDX,     "X86_EDX"    },
    { CorePrStatus::REGISTERS::X86_ESI,     "X86_ESI"    },
    { CorePrStatus::REGISTERS::X86_EDI,     "X86_EDI"    },
    { CorePrStatus::REGISTERS::X86_EBP,     "X86_EBP"    },
    { CorePrStatus::REGISTERS::X86_EAX,     "X86_EAX"    },
    { CorePrStatus::REGISTERS::X86_DS,      "X86_DS"     },
    { CorePrStatus::REGISTERS::X86_ES,      "X86_ES"     },
    { CorePrStatus::REGISTERS::X86_FS,      "X86_FS"     },
    { CorePrStatus::REGISTERS::X86_GS,      "X86_GS"     },
    { CorePrStatus::REGISTERS::X86__,       "X86__"      },
    { CorePrStatus::REGISTERS::X86_EIP,     "X86_EIP"    },
    { CorePrStatus::REGISTERS::X86_CS,      "X86_CS"     },
    { CorePrStatus::REGISTERS::X86_EFLAGS,  "X86_EFLAGS" },
    { CorePrStatus::REGISTERS::X86_ESP,     "X86_ESP"    },
    { CorePrStatus::REGISTERS::X86_SS,      "X86_SS"     },


    { CorePrStatus::REGISTERS::X86_64_R15,    "X86_64_R15"    },
    { CorePrStatus::REGISTERS::X86_64_R14,    "X86_64_R14"    },
    { CorePrStatus::REGISTERS::X86_64_R13,    "X86_64_R13"    },
    { CorePrStatus::REGISTERS::X86_64_R12,    "X86_64_R12"    },
    { CorePrStatus::REGISTERS::X86_64_RBP,    "X86_64_RBP"    },
    { CorePrStatus::REGISTERS::X86_64_RBX,    "X86_64_RBX"    },
    { CorePrStatus::REGISTERS::X86_64_R11,    "X86_64_R11"    },
    { CorePrStatus::REGISTERS::X86_64_R10,    "X86_64_R10"    },
    { CorePrStatus::REGISTERS::X86_64_R9,     "X86_64_R9"     },
    { CorePrStatus::REGISTERS::X86_64_R8,     "X86_64_R8"     },
    { CorePrStatus::REGISTERS::X86_64_RAX,    "X86_64_RAX"    },
    { CorePrStatus::REGISTERS::X86_64_RCX,    "X86_64_RCX"    },
    { CorePrStatus::REGISTERS::X86_64_RDX,    "X86_64_RDX"    },
    { CorePrStatus::REGISTERS::X86_64_RSI,    "X86_64_RSI"    },
    { CorePrStatus::REGISTERS::X86_64_RDI,    "X86_64_RDI"    },
    { CorePrStatus::REGISTERS::X86_64__,      "X86_64__"      },
    { CorePrStatus::REGISTERS::X86_64_RIP,    "X86_64_RIP"    },
    { CorePrStatus::REGISTERS::X86_64_CS,     "X86_64_CS"     },
    { CorePrStatus::REGISTERS::X86_64_EFLAGS, "X86_64_EFLAGS" },
    { CorePrStatus::REGISTERS::X86_64_RSP,    "X86_64_RSP"    },
    { CorePrStatus::REGISTERS::X86_64_SS,     "X86_64_SS"     },

    { CorePrStatus::REGISTERS::ARM_R0,  "ARM_R0"  },
    { CorePrStatus::REGISTERS::ARM_R1,  "ARM_R1"  },
    { CorePrStatus::REGISTERS::ARM_R2,  "ARM_R2"  },
    { CorePrStatus::REGISTERS::ARM_R3,  "ARM_R3"  },
    { CorePrStatus::REGISTERS::ARM_R4,  "ARM_R4"  },
    { CorePrStatus::REGISTERS::ARM_R5,  "ARM_R5"  },
    { CorePrStatus::REGISTERS::ARM_R6,  "ARM_R6"  },
    { CorePrStatus::REGISTERS::ARM_R7,  "ARM_R7"  },
    { CorePrStatus::REGISTERS::ARM_R8,  "ARM_R8"  },
    { CorePrStatus::REGISTERS::ARM_R9,  "ARM_R9"  },
    { CorePrStatus::REGISTERS::ARM_R10, "ARM_R10" },
    { CorePrStatus::REGISTERS::ARM_R11, "ARM_R11" },
    { CorePrStatus::REGISTERS::ARM_R12, "ARM_R12" },
    { CorePrStatus::REGISTERS::ARM_R13, "ARM_R13" },
    { CorePrStatus::REGISTERS::ARM_R14, "ARM_R14" },
    { CorePrStatus::REGISTERS::ARM_R15, "ARM_R15" },
    { CorePrStatus::REGISTERS::ARM_CPSR, "ARM_CPSR" },

    { CorePrStatus::REGISTERS::AARCH64_X0,  "AARCH64_X0"   },
    { CorePrStatus::REGISTERS::AARCH64_X1,  "AARCH64_X1"   },
    { CorePrStatus::REGISTERS::AARCH64_X2,  "AARCH64_X2"   },
    { CorePrStatus::REGISTERS::AARCH64_X3,  "AARCH64_X3"   },
    { CorePrStatus::REGISTERS::AARCH64_X4,  "AARCH64_X4"   },
    { CorePrStatus::REGISTERS::AARCH64_X5,  "AARCH64_X5"   },
    { CorePrStatus::REGISTERS::AARCH64_X6,  "AARCH64_X6"   },
    { CorePrStatus::REGISTERS::AARCH64_X7,  "AARCH64_X7"   },
    { CorePrStatus::REGISTERS::AARCH64_X8,  "AARCH64_X8"   },
    { CorePrStatus::REGISTERS::AARCH64_X9,  "AARCH64_X9"   },
    { CorePrStatus::REGISTERS::AARCH64_X10, "AARCH64_X10"  },
    { CorePrStatus::REGISTERS::AARCH64_X11, "AARCH64_X11"  },
    { CorePrStatus::REGISTERS::AARCH64_X12, "AARCH64_X12"  },
    { CorePrStatus::REGISTERS::AARCH64_X13, "AARCH64_X13"  },
    { CorePrStatus::REGISTERS::AARCH64_X14, "AARCH64_X14"  },
    { CorePrStatus::REGISTERS::AARCH64_X15, "AARCH64_X15"  },
    { CorePrStatus::REGISTERS::AARCH64_X16, "AARCH64_X16"  },
    { CorePrStatus::REGISTERS::AARCH64_X17, "AARCH64_X17"  },
    { CorePrStatus::REGISTERS::AARCH64_X18, "AARCH64_X18"  },
    { CorePrStatus::REGISTERS::AARCH64_X19, "AARCH64_X19"  },
    { CorePrStatus::REGISTERS::AARCH64_X20, "AARCH64_X20"  },
    { CorePrStatus::REGISTERS::AARCH64_X21, "AARCH64_X21"  },
    { CorePrStatus::REGISTERS::AARCH64_X22, "AARCH64_X22"  },
    { CorePrStatus::REGISTERS::AARCH64_X23, "AARCH64_X23"  },
    { CorePrStatus::REGISTERS::AARCH64_X24, "AARCH64_X24"  },
    { CorePrStatus::REGISTERS::AARCH64_X25, "AARCH64_X25"  },
    { CorePrStatus::REGISTERS::AARCH64_X26, "AARCH64_X26"  },
    { CorePrStatus::REGISTERS::AARCH64_X27, "AARCH64_X27"  },
    { CorePrStatus::REGISTERS::AARCH64_X28, "AARCH64_X28"  },
    { CorePrStatus::REGISTERS::AARCH64_X29, "AARCH64_X29"  },
    { CorePrStatus::REGISTERS::AARCH64_X30, "AARCH64_X30"  },
    { CorePrStatus::REGISTERS::AARCH64_X31, "AARCH64_X31"  },
    { CorePrStatus::REGISTERS::AARCH64_PC,  "AARCH64_PC"   },
    { CorePrStatus::REGISTERS::AARCH64__,   "AARCH64__"    },

  };

  const auto it = enum_strings.find(e);
  return it == enum_strings.end() ? "UNKNOWN" : it->second;
}





} // namespace ELF
} // namespace LIEF



