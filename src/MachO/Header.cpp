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

#include <map>
#include <set>
#include <algorithm>
#include <iterator>
#include <string>

#include "fmt_formatter.hpp"
#include "frozen.hpp"
#include "spdlog/fmt/fmt.h"

#include "LIEF/Visitor.hpp"
#include "LIEF/MachO/Header.hpp"
#include "MachO/Structures.hpp"

FMT_FORMATTER(LIEF::MachO::Header::FLAGS, LIEF::MachO::to_string);

namespace LIEF {
namespace MachO {

static constexpr auto HEADER_FLAGS = {
  Header::FLAGS::NOUNDEFS, Header::FLAGS::INCRLINK,
  Header::FLAGS::DYLDLINK, Header::FLAGS::BINDATLOAD,
  Header::FLAGS::PREBOUND, Header::FLAGS::SPLIT_SEGS,
  Header::FLAGS::LAZY_INIT, Header::FLAGS::TWOLEVEL,
  Header::FLAGS::FORCE_FLAT, Header::FLAGS::NOMULTIDEFS,
  Header::FLAGS::NOFIXPREBINDING, Header::FLAGS::PREBINDABLE,
  Header::FLAGS::ALLMODSBOUND, Header::FLAGS::SUBSECTIONS_VIA_SYMBOLS,
  Header::FLAGS::CANONICAL, Header::FLAGS::WEAK_DEFINES,
  Header::FLAGS::BINDS_TO_WEAK, Header::FLAGS::ALLOW_STACK_EXECUTION,
  Header::FLAGS::ROOT_SAFE, Header::FLAGS::SETUID_SAFE,
  Header::FLAGS::NO_REEXPORTED_DYLIBS, Header::FLAGS::PIE,
  Header::FLAGS::DEAD_STRIPPABLE_DYLIB, Header::FLAGS::HAS_TLV_DESCRIPTORS,
  Header::FLAGS::NO_HEAP_EXECUTION, Header::FLAGS::APP_EXTENSION_SAFE,
};

template<class T>
Header::Header(const T& header) :
  magic_{static_cast<MACHO_TYPES>(header.magic)},
  cputype_(static_cast<CPU_TYPE>(header.cputype)),
  cpusubtype_{header.cpusubtype},
  filetype_{static_cast<FILE_TYPE>(header.filetype)},
  ncmds_{header.ncmds},
  sizeofcmds_{header.sizeofcmds},
  flags_{header.flags}
{
  if constexpr (std::is_same_v<T, details::mach_header_64>) {
    reserved_ = header.reserved;
  } else {
    reserved_ = 0;
  }
}

template Header::Header(const details::mach_header_64& header);
template Header::Header(const details::mach_header& header);

std::pair<ARCHITECTURES, std::set<MODES>> Header::abstract_architecture() const {
  using modes_t = std::pair<ARCHITECTURES, std::set<MODES>>;
  static const std::map<CPU_TYPE, modes_t> ARCH_MACHO_TO_LIEF {
    {CPU_TYPE::ANY,       {ARCH_NONE,  {}}},
    {CPU_TYPE::X86_64,    {ARCH_X86,   {MODE_64}}},
    {CPU_TYPE::ARM,       {ARCH_ARM,   {MODE_32}}},
    {CPU_TYPE::ARM64,     {ARCH_ARM64, {MODE_64}}},
    {CPU_TYPE::X86,       {ARCH_X86,   {MODE_32}}},
    {CPU_TYPE::SPARC,     {ARCH_SPARC, {}}},
    {CPU_TYPE::POWERPC,   {ARCH_PPC,   {MODE_32}}},
    {CPU_TYPE::POWERPC64, {ARCH_PPC,   {MODE_64}}},
  };
  auto it = ARCH_MACHO_TO_LIEF.find(cpu_type());
  if (it == std::end(ARCH_MACHO_TO_LIEF)) {
    return {ARCHITECTURES::ARCH_NONE, {}};
  }
  return it->second;
}


OBJECT_TYPES Header::abstract_object_type() const {
  CONST_MAP(FILE_TYPE, OBJECT_TYPES, 3) OBJ_MACHO_TO_LIEF {
    {FILE_TYPE::EXECUTE, OBJECT_TYPES::TYPE_EXECUTABLE},
    {FILE_TYPE::DYLIB,   OBJECT_TYPES::TYPE_LIBRARY},
    {FILE_TYPE::OBJECT,  OBJECT_TYPES::TYPE_OBJECT},
  };
  auto it = OBJ_MACHO_TO_LIEF.find(file_type());
  if (it == std::end(OBJ_MACHO_TO_LIEF)) {
    return OBJECT_TYPES::TYPE_NONE;
  }
  return it->second;
}

ENDIANNESS Header::abstract_endianness() const {
  CONST_MAP(CPU_TYPE, ENDIANNESS, 7) ENDI_MACHO_TO_LIEF {
    {CPU_TYPE::X86,       ENDIANNESS::ENDIAN_LITTLE},
    {CPU_TYPE::X86_64,    ENDIANNESS::ENDIAN_LITTLE},
    {CPU_TYPE::ARM,       ENDIANNESS::ENDIAN_LITTLE},
    {CPU_TYPE::ARM64,     ENDIANNESS::ENDIAN_LITTLE},
    {CPU_TYPE::SPARC,     ENDIANNESS::ENDIAN_BIG},
    {CPU_TYPE::POWERPC,   ENDIANNESS::ENDIAN_BIG},
    {CPU_TYPE::POWERPC64, ENDIANNESS::ENDIAN_BIG},
  };
  auto it = ENDI_MACHO_TO_LIEF.find(cpu_type());
  if (it == std::end(ENDI_MACHO_TO_LIEF)) {
    return ENDIANNESS::ENDIAN_NONE;
  }
  auto not_endianness = [] (ENDIANNESS endian) {
    return endian == ENDIAN_LITTLE ? ENDIAN_BIG : ENDIAN_LITTLE;
  };
  if (magic() == MACHO_TYPES::MH_CIGAM ||
      magic() == MACHO_TYPES::MH_CIGAM_64 ||
      magic() == MACHO_TYPES::FAT_CIGAM)
  {
    return not_endianness(it->second);
  }
  return it->second;
}

std::vector<Header::FLAGS> Header::flags_list() const {
  std::vector<Header::FLAGS> flags;

  std::copy_if(std::begin(HEADER_FLAGS), std::end(HEADER_FLAGS),
               std::inserter(flags, std::begin(flags)),
               [this] (FLAGS f) { return has(f); });

  return flags;
}


bool Header::has(FLAGS flag) const {
  return (flags() & static_cast<uint32_t>(flag)) > 0;
}

void Header::add(FLAGS flag) {
  flags(flags() | static_cast<uint32_t>(flag));
}

void Header::remove(FLAGS flag) {
  flags(flags() & ~static_cast<uint32_t>(flag));
}

void Header::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const Header& hdr) {
  os << fmt::format("Magic: 0x{:08x}\n", uint32_t(hdr.magic()));
  os << fmt::format("CPU: {}\n", to_string(hdr.cpu_type()));
  os << fmt::format("CPU subtype: 0x{:08x}\n", hdr.cpu_subtype());
  os << fmt::format("File type: {}\n", to_string(hdr.file_type()));
  os << fmt::format("Flags: {}\n", hdr.flags());
  os << fmt::format("Reserved: 0x{:x}\n", hdr.reserved());
  os << fmt::format("Nb cmds: {}\n", hdr.nb_cmds());
  os << fmt::format("Sizeof cmds: {}\n", hdr.sizeof_cmds());
  return os;
}

const char* to_string(Header::FLAGS e) {
  #define ENTRY(X) std::pair(Header::FLAGS::X, #X)
  STRING_MAP enums2str {
    ENTRY(NOUNDEFS),
    ENTRY(INCRLINK),
    ENTRY(DYLDLINK),
    ENTRY(BINDATLOAD),
    ENTRY(PREBOUND),
    ENTRY(SPLIT_SEGS),
    ENTRY(LAZY_INIT),
    ENTRY(TWOLEVEL),
    ENTRY(FORCE_FLAT),
    ENTRY(NOMULTIDEFS),
    ENTRY(NOFIXPREBINDING),
    ENTRY(PREBINDABLE),
    ENTRY(ALLMODSBOUND),
    ENTRY(SUBSECTIONS_VIA_SYMBOLS),
    ENTRY(CANONICAL),
    ENTRY(WEAK_DEFINES),
    ENTRY(BINDS_TO_WEAK),
    ENTRY(ALLOW_STACK_EXECUTION),
    ENTRY(ROOT_SAFE),
    ENTRY(SETUID_SAFE),
    ENTRY(NO_REEXPORTED_DYLIBS),
    ENTRY(PIE),
    ENTRY(DEAD_STRIPPABLE_DYLIB),
    ENTRY(HAS_TLV_DESCRIPTORS),
    ENTRY(NO_HEAP_EXECUTION),
    ENTRY(APP_EXTENSION_SAFE),
  };
  #undef ENTRY

  if (auto it = enums2str.find(e); it != enums2str.end()) {
    return it->second;
  }
  return "UNKNOWN";
}

const char* to_string(Header::FILE_TYPE e) {
  #define ENTRY(X) std::pair(Header::FILE_TYPE::X, #X)
  STRING_MAP enums2str {
    ENTRY(UNKNOWN),
    ENTRY(OBJECT),
    ENTRY(EXECUTE),
    ENTRY(FVMLIB),
    ENTRY(CORE),
    ENTRY(PRELOAD),
    ENTRY(DYLIB),
    ENTRY(DYLINKER),
    ENTRY(BUNDLE),
    ENTRY(DYLIB_STUB),
    ENTRY(DSYM),
    ENTRY(KEXT_BUNDLE),
  };
  #undef ENTRY

  if (auto it = enums2str.find(e); it != enums2str.end()) {
    return it->second;
  }
  return "UNKNOWN";
}

const char* to_string(Header::CPU_TYPE e) {
  #define ENTRY(X) std::pair(Header::CPU_TYPE::X, #X)
  STRING_MAP enums2str {
    ENTRY(ANY),
    ENTRY(X86),
    ENTRY(X86_64),
    ENTRY(MIPS),
    ENTRY(MC98000),
    ENTRY(ARM),
    ENTRY(ARM64),
    ENTRY(SPARC),
    ENTRY(POWERPC),
    ENTRY(POWERPC64),
  };
  #undef ENTRY

  if (auto it = enums2str.find(e); it != enums2str.end()) {
    return it->second;
  }
  return "UNKNOWN";
}

}
}
