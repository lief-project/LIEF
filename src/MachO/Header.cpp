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
#include <map>
#include <set>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <iterator>
#include <string>

#include "LIEF/exception.hpp"

#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/Header.hpp"
#include "LIEF/MachO/EnumToString.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

static const std::map<CPU_TYPES, std::pair<ARCHITECTURES, std::set<MODES>>> arch_macho_to_lief {
  {CPU_TYPES::CPU_TYPE_ANY,       {ARCH_NONE,  {}}},
  {CPU_TYPES::CPU_TYPE_X86_64,    {ARCH_X86,   {MODE_64}}},
  {CPU_TYPES::CPU_TYPE_ARM,       {ARCH_ARM,   {MODE_32}}},
  {CPU_TYPES::CPU_TYPE_ARM64,     {ARCH_ARM64, {MODE_64}}},
  {CPU_TYPES::CPU_TYPE_X86,       {ARCH_X86,   {MODE_32}}},
  {CPU_TYPES::CPU_TYPE_SPARC,     {ARCH_SPARC, {}}},
  {CPU_TYPES::CPU_TYPE_POWERPC,   {ARCH_PPC,   {MODE_32}}},
  {CPU_TYPES::CPU_TYPE_POWERPC64, {ARCH_PPC,   {MODE_64}}},
};

static const std::map<FILE_TYPES, OBJECT_TYPES> obj_macho_to_lief {
  {FILE_TYPES::MH_EXECUTE, OBJECT_TYPES::TYPE_EXECUTABLE},
  {FILE_TYPES::MH_DYLIB,   OBJECT_TYPES::TYPE_LIBRARY},
  {FILE_TYPES::MH_OBJECT,  OBJECT_TYPES::TYPE_OBJECT},
};

static const std::map<CPU_TYPES, ENDIANNESS> endi_macho_to_lief {
  {CPU_TYPES::CPU_TYPE_X86,       ENDIANNESS::ENDIAN_LITTLE},
  {CPU_TYPES::CPU_TYPE_I386,      ENDIANNESS::ENDIAN_LITTLE},
  {CPU_TYPES::CPU_TYPE_X86_64,    ENDIANNESS::ENDIAN_LITTLE},
  {CPU_TYPES::CPU_TYPE_ARM,       ENDIANNESS::ENDIAN_LITTLE},
  {CPU_TYPES::CPU_TYPE_ARM64,     ENDIANNESS::ENDIAN_LITTLE},
  {CPU_TYPES::CPU_TYPE_SPARC,     ENDIANNESS::ENDIAN_BIG},
  {CPU_TYPES::CPU_TYPE_POWERPC,   ENDIANNESS::ENDIAN_BIG},
  {CPU_TYPES::CPU_TYPE_POWERPC64, ENDIANNESS::ENDIAN_BIG},
};


Header::Header() = default;
Header& Header::operator=(const Header&) = default;
Header::Header(const Header&) = default;
Header::~Header() = default;

Header::Header(const details::mach_header_64& header) :
  magic_{static_cast<MACHO_TYPES>(header.magic)},
  cputype_(static_cast<CPU_TYPES>(header.cputype)),
  cpusubtype_{header.cpusubtype},
  filetype_{static_cast<FILE_TYPES>(header.filetype)},
  ncmds_{header.ncmds},
  sizeofcmds_{header.sizeofcmds},
  flags_{header.flags},
  reserved_{header.reserved}
{}

Header::Header(const details::mach_header& header) :
  magic_{static_cast<MACHO_TYPES>(header.magic)},
  cputype_(static_cast<CPU_TYPES>(header.cputype)),
  cpusubtype_{header.cpusubtype},
  filetype_{static_cast<FILE_TYPES>(header.filetype)},
  ncmds_{header.ncmds},
  sizeofcmds_{header.sizeofcmds},
  flags_{header.flags},
  reserved_{0}
{}


MACHO_TYPES Header::magic() const {
  return magic_;
}
CPU_TYPES Header::cpu_type() const {
  return cputype_;
}

uint32_t Header::cpu_subtype() const {
  return cpusubtype_;
}

FILE_TYPES Header::file_type() const {
  return filetype_;
}

uint32_t Header::nb_cmds() const {
  return ncmds_;
}

uint32_t Header::sizeof_cmds() const {
  return sizeofcmds_;
}

uint32_t Header::flags() const {
  return flags_;
}

uint32_t Header::reserved() const {
  return reserved_;
}

std::pair<ARCHITECTURES, std::set<MODES>> Header::abstract_architecture() const {
  auto it = arch_macho_to_lief.find(cpu_type());
  if (it == std::end(arch_macho_to_lief)) {
    return {ARCHITECTURES::ARCH_NONE, {}};
  }
  return it->second;
}


OBJECT_TYPES Header::abstract_object_type() const {
  auto it = obj_macho_to_lief.find(file_type());
  if (it == std::end(obj_macho_to_lief)) {
    return OBJECT_TYPES::TYPE_NONE;
  }
  return it->second;
}

ENDIANNESS Header::abstract_endianness() const {
  ENDIANNESS e = endi_macho_to_lief.at(cpu_type());
  auto not_endianness = [] (ENDIANNESS endian) {
    return endian == ENDIAN_LITTLE ? ENDIAN_BIG : ENDIAN_LITTLE;
  };
  if (magic() == MACHO_TYPES::MH_CIGAM ||
      magic() == MACHO_TYPES::MH_CIGAM_64 ||
      magic() == MACHO_TYPES::FAT_CIGAM)
  {
    return not_endianness(e);
  }
  return e;
}


Header::flags_list_t Header::flags_list() const {
  Header::flags_list_t flags;

  std::copy_if(std::begin(header_flags_array), std::end(header_flags_array),
               std::inserter(flags, std::begin(flags)),
               [this] (HEADER_FLAGS f) { return has(f); });

  return flags;
}


bool Header::has(HEADER_FLAGS flag) const {
  return (flags() & static_cast<uint32_t>(flag)) > 0;
}


void Header::add(HEADER_FLAGS flag) {
  flags(flags() | static_cast<uint32_t>(flag));
}

void Header::remove(HEADER_FLAGS flag) {
  flags(flags() & ~static_cast<uint32_t>(flag));
}


void Header::magic(MACHO_TYPES magic) {
  magic_ = magic;
}
void Header::cpu_type(CPU_TYPES cputype) {
  cputype_ = cputype;
}

void Header::cpu_subtype(uint32_t cpusubtype) {
  cpusubtype_ = cpusubtype;
}

void Header::file_type(FILE_TYPES filetype) {
  filetype_ = filetype;
}

void Header::nb_cmds(uint32_t ncmds) {
  ncmds_ = ncmds;
}

void Header::sizeof_cmds(uint32_t sizeofcmds) {
  sizeofcmds_ = sizeofcmds;
}

void Header::flags(uint32_t flags) {
  flags_ = flags;
}

void Header::reserved(uint32_t reserved) {
  reserved_ = reserved;
}


void Header::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool Header::operator==(const Header& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Header::operator!=(const Header& rhs) const {
  return !(*this == rhs);
}


Header& Header::operator+=(HEADER_FLAGS c) {
  add(c);
  return *this;
}

Header& Header::operator-=(HEADER_FLAGS c) {
  remove(c);
  return *this;
}


std::ostream& operator<<(std::ostream& os, const Header& hdr) {

  const auto& flags = hdr.flags_list();

 std::string flags_str = std::accumulate(
     std::begin(flags), std::end(flags), std::string{},
     [] (const std::string& a, HEADER_FLAGS b) {
         return a.empty() ? to_string(b) : a + " " + to_string(b);
     });

  os << std::hex;
  os << std::left
     << std::setw(10) << "Magic"
     << std::setw(10) << "CPU Type"
     << std::setw(15) << "CPU subtype"
     << std::setw(15) << "File type"
     << std::setw(10) << "NCMDS"
     << std::setw(15) << "Sizeof cmds"
     << std::setw(10) << "Reserved"
     << std::setw(10) << "Flags" << std::endl

     << std::setw(10) << to_string(hdr.magic())
     << std::setw(10) << to_string(hdr.cpu_type())
     << std::setw(15) << hdr.cpu_subtype()
     << std::setw(15) << to_string(hdr.file_type())
     << std::setw(10) << hdr.nb_cmds()
     << std::setw(15) << hdr.sizeof_cmds()
     << std::setw(10) << hdr.reserved()
     << std::setw(10) << flags_str
     << std::endl;

  return os;
}

}
}
