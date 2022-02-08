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
/* From llvm/Support/ELF.h */
#ifndef LIEF_ELF_STRUCTURES_H_
#define LIEF_ELF_STRUCTURES_H_

#include <cstring>

#include "LIEF/types.hpp"
#include "LIEF/ELF/enums.hpp"

namespace LIEF {
//! @brief Namespace related to the LIEF's ELF module
namespace ELF {

namespace details {

#include "structures.inc"

static const ELF_SECTION_FLAGS section_flags_array[] = {
  ELF_SECTION_FLAGS::SHF_NONE, ELF_SECTION_FLAGS::SHF_WRITE, ELF_SECTION_FLAGS::SHF_ALLOC, ELF_SECTION_FLAGS::SHF_EXECINSTR,
   ELF_SECTION_FLAGS::SHF_MERGE, ELF_SECTION_FLAGS::SHF_STRINGS, ELF_SECTION_FLAGS::SHF_INFO_LINK,
   ELF_SECTION_FLAGS::SHF_LINK_ORDER, ELF_SECTION_FLAGS::SHF_OS_NONCONFORMING, ELF_SECTION_FLAGS::SHF_GROUP,
   ELF_SECTION_FLAGS::SHF_TLS, ELF_SECTION_FLAGS::SHF_EXCLUDE, ELF_SECTION_FLAGS::XCORE_SHF_CP_SECTION,
   ELF_SECTION_FLAGS::XCORE_SHF_DP_SECTION, ELF_SECTION_FLAGS::SHF_MASKOS, ELF_SECTION_FLAGS::SHF_MASKPROC,
   ELF_SECTION_FLAGS::SHF_HEX_GPREL, ELF_SECTION_FLAGS::SHF_MIPS_NODUPES, ELF_SECTION_FLAGS::SHF_MIPS_NAMES,
   ELF_SECTION_FLAGS::SHF_MIPS_LOCAL, ELF_SECTION_FLAGS::SHF_MIPS_NOSTRIP, ELF_SECTION_FLAGS::SHF_MIPS_GPREL,
   ELF_SECTION_FLAGS::SHF_MIPS_MERGE, ELF_SECTION_FLAGS::SHF_MIPS_ADDR, ELF_SECTION_FLAGS::SHF_MIPS_STRING
};


static const ARM_EFLAGS arm_eflags_array[] = {
  ARM_EFLAGS::EF_ARM_SOFT_FLOAT,
  ARM_EFLAGS::EF_ARM_VFP_FLOAT,
  ARM_EFLAGS::EF_ARM_EABI_UNKNOWN,
  ARM_EFLAGS::EF_ARM_EABI_VER1,
  ARM_EFLAGS::EF_ARM_EABI_VER2,
  ARM_EFLAGS::EF_ARM_EABI_VER3,
  ARM_EFLAGS::EF_ARM_EABI_VER4,
  ARM_EFLAGS::EF_ARM_EABI_VER5,
};

static const PPC64_EFLAGS ppc64_eflags_array[] = {
  PPC64_EFLAGS::EF_PPC64_ABI,
};

static const MIPS_EFLAGS mips_eflags_array[] = {
  MIPS_EFLAGS::EF_MIPS_NOREORDER,
  MIPS_EFLAGS::EF_MIPS_PIC,
  MIPS_EFLAGS::EF_MIPS_CPIC,
  MIPS_EFLAGS::EF_MIPS_ABI2,
  MIPS_EFLAGS::EF_MIPS_32BITMODE,
  MIPS_EFLAGS::EF_MIPS_FP64,
  MIPS_EFLAGS::EF_MIPS_NAN2008,
  MIPS_EFLAGS::EF_MIPS_ABI_O32,
  MIPS_EFLAGS::EF_MIPS_ABI_O64,
  MIPS_EFLAGS::EF_MIPS_ABI_EABI32,
  MIPS_EFLAGS::EF_MIPS_ABI_EABI64,
  MIPS_EFLAGS::EF_MIPS_MACH_3900,
  MIPS_EFLAGS::EF_MIPS_MACH_4010,
  MIPS_EFLAGS::EF_MIPS_MACH_4100,
  MIPS_EFLAGS::EF_MIPS_MACH_4650,
  MIPS_EFLAGS::EF_MIPS_MACH_4120,
  MIPS_EFLAGS::EF_MIPS_MACH_4111,
  MIPS_EFLAGS::EF_MIPS_MACH_SB1,
  MIPS_EFLAGS::EF_MIPS_MACH_OCTEON,
  MIPS_EFLAGS::EF_MIPS_MACH_XLR,
  MIPS_EFLAGS::EF_MIPS_MACH_OCTEON2,
  MIPS_EFLAGS::EF_MIPS_MACH_OCTEON3,
  MIPS_EFLAGS::EF_MIPS_MACH_5400,
  MIPS_EFLAGS::EF_MIPS_MACH_5900,
  MIPS_EFLAGS::EF_MIPS_MACH_5500,
  MIPS_EFLAGS::EF_MIPS_MACH_9000,
  MIPS_EFLAGS::EF_MIPS_MACH_LS2E,
  MIPS_EFLAGS::EF_MIPS_MACH_LS2F,
  MIPS_EFLAGS::EF_MIPS_MACH_LS3A,
  MIPS_EFLAGS::EF_MIPS_MICROMIPS,
  MIPS_EFLAGS::EF_MIPS_ARCH_ASE_M16,
  MIPS_EFLAGS::EF_MIPS_ARCH_ASE_MDMX,
  MIPS_EFLAGS::EF_MIPS_ARCH_1,
  MIPS_EFLAGS::EF_MIPS_ARCH_2,
  MIPS_EFLAGS::EF_MIPS_ARCH_3,
  MIPS_EFLAGS::EF_MIPS_ARCH_4,
  MIPS_EFLAGS::EF_MIPS_ARCH_5,
  MIPS_EFLAGS::EF_MIPS_ARCH_32,
  MIPS_EFLAGS::EF_MIPS_ARCH_64,
  MIPS_EFLAGS::EF_MIPS_ARCH_32R2,
  MIPS_EFLAGS::EF_MIPS_ARCH_64R2,
  MIPS_EFLAGS::EF_MIPS_ARCH_32R6,
  MIPS_EFLAGS::EF_MIPS_ARCH_64R6,
};

static const HEXAGON_EFLAGS hexagon_eflags_array[] = {
  HEXAGON_EFLAGS::EF_HEXAGON_MACH_V2,
  HEXAGON_EFLAGS::EF_HEXAGON_MACH_V3,
  HEXAGON_EFLAGS::EF_HEXAGON_MACH_V4,
  HEXAGON_EFLAGS::EF_HEXAGON_MACH_V5,
  HEXAGON_EFLAGS::EF_HEXAGON_ISA_MACH,
  HEXAGON_EFLAGS::EF_HEXAGON_ISA_V2,
  HEXAGON_EFLAGS::EF_HEXAGON_ISA_V3,
  HEXAGON_EFLAGS::EF_HEXAGON_ISA_V4,
  HEXAGON_EFLAGS::EF_HEXAGON_ISA_V5,
};

static const DYNAMIC_FLAGS dynamic_flags_array[] = {
  DYNAMIC_FLAGS::DF_ORIGIN,
  DYNAMIC_FLAGS::DF_SYMBOLIC,
  DYNAMIC_FLAGS::DF_TEXTREL,
  DYNAMIC_FLAGS::DF_BIND_NOW,
  DYNAMIC_FLAGS::DF_STATIC_TLS,
};


static const DYNAMIC_FLAGS_1 dynamic_flags_1_array[] = {
  DYNAMIC_FLAGS_1::DF_1_NOW,
  DYNAMIC_FLAGS_1::DF_1_GLOBAL,
  DYNAMIC_FLAGS_1::DF_1_GROUP,
  DYNAMIC_FLAGS_1::DF_1_NODELETE,
  DYNAMIC_FLAGS_1::DF_1_LOADFLTR,
  DYNAMIC_FLAGS_1::DF_1_INITFIRST,
  DYNAMIC_FLAGS_1::DF_1_NOOPEN,
  DYNAMIC_FLAGS_1::DF_1_ORIGIN,
  DYNAMIC_FLAGS_1::DF_1_DIRECT,
  DYNAMIC_FLAGS_1::DF_1_TRANS,
  DYNAMIC_FLAGS_1::DF_1_INTERPOSE,
  DYNAMIC_FLAGS_1::DF_1_NODEFLIB,
  DYNAMIC_FLAGS_1::DF_1_NODUMP,
  DYNAMIC_FLAGS_1::DF_1_CONFALT,
  DYNAMIC_FLAGS_1::DF_1_ENDFILTEE,
  DYNAMIC_FLAGS_1::DF_1_DISPRELDNE,
  DYNAMIC_FLAGS_1::DF_1_DISPRELPND,
  DYNAMIC_FLAGS_1::DF_1_NODIRECT,
  DYNAMIC_FLAGS_1::DF_1_IGNMULDEF,
  DYNAMIC_FLAGS_1::DF_1_NOKSYMS,
  DYNAMIC_FLAGS_1::DF_1_NOHDR,
  DYNAMIC_FLAGS_1::DF_1_EDITED,
  DYNAMIC_FLAGS_1::DF_1_NORELOC,
  DYNAMIC_FLAGS_1::DF_1_SYMINTPOSE,
  DYNAMIC_FLAGS_1::DF_1_GLOBAUDIT,
  DYNAMIC_FLAGS_1::DF_1_SINGLETON,
  DYNAMIC_FLAGS_1::DF_1_PIE,
};



class ELF32 {
  public:
  typedef Elf32_Addr    Elf_Addr;
  typedef Elf32_Off     Elf_Off;
  typedef Elf32_Half    Elf_Half;
  typedef Elf32_Word    Elf_Word;
  typedef Elf32_Sword   Elf_Sword;
  // Equivalent
  typedef Elf32_Addr    Elf_Xword;
  typedef Elf32_Sword   Elf_Sxword;

  typedef uint32_t      uint;

  typedef Elf32_Phdr    Elf_Phdr;
  typedef Elf32_Ehdr    Elf_Ehdr;
  typedef Elf32_Shdr    Elf_Shdr;
  typedef Elf32_Sym     Elf_Sym;
  typedef Elf32_Rel     Elf_Rel;
  typedef Elf32_Rela    Elf_Rela;
  typedef Elf32_Dyn     Elf_Dyn;
  typedef Elf32_Verneed Elf_Verneed;
  typedef Elf32_Vernaux Elf_Vernaux;
  typedef Elf32_Auxv    Elf_Auxv;
  typedef Elf32_Verdef  Elf_Verdef;
  typedef Elf32_Verdaux Elf_Verdaux;

  typedef Elf32_Prpsinfo  Elf_Prpsinfo;
  typedef Elf32_FileEntry Elf_FileEntry;
  typedef Elf32_Prstatus  Elf_Prstatus;

  typedef Elf32_timeval   Elf_timeval;
};


class ELF64 {
  public:
  typedef Elf64_Addr    Elf_Addr;
  typedef Elf64_Off     Elf_Off;
  typedef Elf64_Half    Elf_Half;
  typedef Elf64_Word    Elf_Word;
  typedef Elf64_Sword   Elf_Sword;

  typedef Elf64_Xword   Elf_Xword;
  typedef Elf64_Sxword  Elf_Sxword;

  typedef uint64_t      uint;

  typedef Elf64_Phdr    Elf_Phdr;
  typedef Elf64_Ehdr    Elf_Ehdr;
  typedef Elf64_Shdr    Elf_Shdr;
  typedef Elf64_Sym     Elf_Sym;
  typedef Elf64_Rel     Elf_Rel;
  typedef Elf64_Rela    Elf_Rela;
  typedef Elf64_Dyn     Elf_Dyn;
  typedef Elf64_Verneed Elf_Verneed;
  typedef Elf64_Vernaux Elf_Vernaux;
  typedef Elf64_Auxv    Elf_Auxv;
  typedef Elf64_Verdef  Elf_Verdef;
  typedef Elf64_Verdaux Elf_Verdaux;

  typedef Elf64_Prpsinfo  Elf_Prpsinfo;
  typedef Elf64_FileEntry Elf_FileEntry;
  typedef Elf64_Prstatus  Elf_Prstatus;

  typedef Elf64_timeval   Elf_timeval;
 };

} /* end namespace details */
} /* end namespace ELF */
} /* end namespace LIEF */
#endif
