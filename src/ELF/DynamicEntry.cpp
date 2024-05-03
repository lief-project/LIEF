/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include "LIEF/Visitor.hpp"

#include "LIEF/ELF/DynamicEntry.hpp"
#include "ELF/Structures.hpp"

#include <spdlog/fmt/fmt.h>

#include "frozen.hpp"
#include "logging.hpp"

namespace LIEF {
namespace ELF {

DynamicEntry::TAG DynamicEntry::from_value(uint64_t value, ARCH arch) {
  static constexpr auto LOPROC = 0x70000000;
  static constexpr auto HIPROC = 0x7FFFFFFF;

  if (LOPROC <= value && value <= HIPROC) {
    switch (arch) {
      case ARCH::AARCH64:
        return TAG(AARCH64_DISC + value);

      case ARCH::MIPS_RS3_LE:
      case ARCH::MIPS:
        return TAG(MIPS_DISC + value);

      case ARCH::HEXAGON:
        return TAG(HEXAGON_DISC + value);

      case ARCH::PPC:
        return TAG(PPC_DISC + value);

      case ARCH::PPC64:
        return TAG(PPC64_DISC + value);

      case ARCH::RISCV:
        return TAG(RISCV_DISC + value);

      default:
        LIEF_WARN("Dynamic tag: 0x{:04x} is not supported for the "
                  "current architecture", value);
        return TAG::UNKNOWN;
    }
  }

  return TAG(value);
}

uint64_t DynamicEntry::to_value(DynamicEntry::TAG tag) {
  auto raw_value = static_cast<uint64_t>(tag);
  if (MIPS_DISC <= raw_value && raw_value < AARCH64_DISC) {
    return raw_value - MIPS_DISC;
  }

  if (AARCH64_DISC <= raw_value && raw_value < HEXAGON_DISC) {
    return raw_value - AARCH64_DISC;
  }

  if (HEXAGON_DISC <= raw_value && raw_value < PPC_DISC) {
    return raw_value - HEXAGON_DISC;
  }

  if (PPC_DISC <= raw_value && raw_value < PPC64_DISC) {
    return raw_value - PPC_DISC;
  }

  if (PPC64_DISC <= raw_value && raw_value < RISCV_DISC) {
    return raw_value - PPC64_DISC;
  }

  if (RISCV_DISC <= raw_value) {
    return raw_value - RISCV_DISC;
  }

  return raw_value;
}

DynamicEntry::DynamicEntry(const details::Elf64_Dyn& header, ARCH arch) :
  tag_{DynamicEntry::from_value(header.d_tag, arch)},
  value_{header.d_un.d_val}
{}

DynamicEntry::DynamicEntry(const details::Elf32_Dyn& header, ARCH arch) :
  tag_{DynamicEntry::from_value(header.d_tag, arch)},
  value_{header.d_un.d_val}
{}

void DynamicEntry::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& DynamicEntry::print(std::ostream& os) const {
  os << fmt::format("{:<20}: 0x{:06x} ", to_string(tag()), value());
  return os;
}

const char* to_string(DynamicEntry::TAG tag) {
  #define ENTRY(X) std::pair(DynamicEntry::TAG::X, #X)
  STRING_MAP enums2str {
    ENTRY(UNKNOWN),
    ENTRY(DT_NULL),
    ENTRY(NEEDED),
    ENTRY(PLTRELSZ),
    ENTRY(PLTGOT),
    ENTRY(HASH),
    ENTRY(STRTAB),
    ENTRY(SYMTAB),
    ENTRY(RELA),
    ENTRY(RELASZ),
    ENTRY(RELAENT),
    ENTRY(STRSZ),
    ENTRY(SYMENT),
    ENTRY(INIT),
    ENTRY(FINI),
    ENTRY(SONAME),
    ENTRY(RPATH),
    ENTRY(SYMBOLIC),
    ENTRY(REL),
    ENTRY(RELSZ),
    ENTRY(RELENT),
    ENTRY(PLTREL),
    ENTRY(DEBUG_TAG),
    ENTRY(TEXTREL),
    ENTRY(JMPREL),
    ENTRY(BIND_NOW),
    ENTRY(INIT_ARRAY),
    ENTRY(FINI_ARRAY),
    ENTRY(INIT_ARRAYSZ),
    ENTRY(FINI_ARRAYSZ),
    ENTRY(RUNPATH),
    ENTRY(FLAGS),
    ENTRY(PREINIT_ARRAY),
    ENTRY(PREINIT_ARRAYSZ),
    ENTRY(SYMTAB_SHNDX),
    ENTRY(RELRSZ),
    ENTRY(RELR),
    ENTRY(RELRENT),
    ENTRY(GNU_HASH),
    ENTRY(RELACOUNT),
    ENTRY(RELCOUNT),
    ENTRY(FLAGS_1),
    ENTRY(VERSYM),
    ENTRY(VERDEF),
    ENTRY(VERDEFNUM),
    ENTRY(VERNEED),
    ENTRY(VERNEEDNUM),
    ENTRY(ANDROID_REL_OFFSET),
    ENTRY(ANDROID_REL_SIZE),
    ENTRY(ANDROID_REL),
    ENTRY(ANDROID_RELSZ),
    ENTRY(ANDROID_RELA),
    ENTRY(ANDROID_RELASZ),
    ENTRY(ANDROID_RELR),
    ENTRY(ANDROID_RELRSZ),
    ENTRY(ANDROID_RELRENT),
    ENTRY(ANDROID_RELRCOUNT),
    ENTRY(MIPS_RLD_VERSION),
    ENTRY(MIPS_TIME_STAMP),
    ENTRY(MIPS_ICHECKSUM),
    ENTRY(MIPS_IVERSION),
    ENTRY(MIPS_FLAGS),
    ENTRY(MIPS_BASE_ADDRESS),
    ENTRY(MIPS_MSYM),
    ENTRY(MIPS_CONFLICT),
    ENTRY(MIPS_LIBLIST),
    ENTRY(MIPS_LOCAL_GOTNO),
    ENTRY(MIPS_CONFLICTNO),
    ENTRY(MIPS_LIBLISTNO),
    ENTRY(MIPS_SYMTABNO),
    ENTRY(MIPS_UNREFEXTNO),
    ENTRY(MIPS_GOTSYM),
    ENTRY(MIPS_HIPAGENO),
    ENTRY(MIPS_RLD_MAP),
    ENTRY(MIPS_DELTA_CLASS),
    ENTRY(MIPS_DELTA_CLASS_NO),
    ENTRY(MIPS_DELTA_INSTANCE),
    ENTRY(MIPS_DELTA_INSTANCE_NO),
    ENTRY(MIPS_DELTA_RELOC),
    ENTRY(MIPS_DELTA_RELOC_NO),
    ENTRY(MIPS_DELTA_SYM),
    ENTRY(MIPS_DELTA_SYM_NO),
    ENTRY(MIPS_DELTA_CLASSSYM),
    ENTRY(MIPS_DELTA_CLASSSYM_NO),
    ENTRY(MIPS_CXX_FLAGS),
    ENTRY(MIPS_PIXIE_INIT),
    ENTRY(MIPS_SYMBOL_LIB),
    ENTRY(MIPS_LOCALPAGE_GOTIDX),
    ENTRY(MIPS_LOCAL_GOTIDX),
    ENTRY(MIPS_HIDDEN_GOTIDX),
    ENTRY(MIPS_PROTECTED_GOTIDX),
    ENTRY(MIPS_OPTIONS),
    ENTRY(MIPS_INTERFACE),
    ENTRY(MIPS_DYNSTR_ALIGN),
    ENTRY(MIPS_INTERFACE_SIZE),
    ENTRY(MIPS_RLD_TEXT_RESOLVE_ADDR),
    ENTRY(MIPS_PERF_SUFFIX),
    ENTRY(MIPS_COMPACT_SIZE),
    ENTRY(MIPS_GP_VALUE),
    ENTRY(MIPS_AUX_DYNAMIC),
    ENTRY(MIPS_PLTGOT),
    ENTRY(MIPS_RWPLT),
    ENTRY(MIPS_RLD_MAP_REL),
    ENTRY(MIPS_XHASH),

    ENTRY(AARCH64_BTI_PLT),
    ENTRY(AARCH64_PAC_PLT),
    ENTRY(AARCH64_VARIANT_PCS),
    ENTRY(AARCH64_MEMTAG_MODE),
    ENTRY(AARCH64_MEMTAG_HEAP),
    ENTRY(AARCH64_MEMTAG_STACK),
    ENTRY(AARCH64_MEMTAG_GLOBALS),
    ENTRY(AARCH64_MEMTAG_GLOBALSSZ),

    ENTRY(HEXAGON_SYMSZ),
    ENTRY(HEXAGON_VER),
    ENTRY(HEXAGON_PLT),

    ENTRY(PPC_GOT),
    ENTRY(PPC_OPT),

    ENTRY(PPC64_GLINK),
    ENTRY(PPC64_OPT),

    ENTRY(RISCV_VARIANT_CC),
  };
  #undef ENTRY

  if (auto it = enums2str.find(tag); it != enums2str.end()) {
    return it->second;
  }

  return "UNKNOWN";
}

}
}
