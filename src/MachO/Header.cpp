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


Header::Header(void) = default;
Header& Header::operator=(const Header&) = default;
Header::Header(const Header&) = default;
Header::~Header(void) = default;

Header::Header(const mach_header_64 *header) :
  magic_{static_cast<MACHO_TYPES>(header->magic)},
  cputype_(static_cast<CPU_TYPES>(header->cputype)),
  cpusubtype_{header->cpusubtype},
  filetype_{static_cast<FILE_TYPES>(header->filetype)},
  ncmds_{header->ncmds},
  sizeofcmds_{header->sizeofcmds},
  flags_{header->flags},
  reserved_{header->reserved}
{}

Header::Header(const mach_header *header) :
  magic_{static_cast<MACHO_TYPES>(header->magic)},
  cputype_(static_cast<CPU_TYPES>(header->cputype)),
  cpusubtype_{header->cpusubtype},
  filetype_{static_cast<FILE_TYPES>(header->filetype)},
  ncmds_{header->ncmds},
  sizeofcmds_{header->sizeofcmds},
  flags_{header->flags},
  reserved_{0}
{}


MACHO_TYPES Header::magic(void) const {
  return this->magic_;
}
CPU_TYPES Header::cpu_type(void) const {
  return this->cputype_;
}

uint32_t Header::cpu_subtype(void) const {
  return this->cpusubtype_;
}

FILE_TYPES Header::file_type(void) const {
  return this->filetype_;
}

uint32_t Header::nb_cmds(void) const {
  return this->ncmds_;
}

uint32_t Header::sizeof_cmds(void) const {
  return this->sizeofcmds_;
}

uint32_t Header::flags(void) const {
  return this->flags_;
}

uint32_t Header::reserved(void) const {
  return this->reserved_;
}

std::pair<ARCHITECTURES, std::set<MODES>> Header::abstract_architecture(void) const {
  if (arch_macho_to_lief.count(this->cpu_type()) != 0) {
    return arch_macho_to_lief.at(this->cpu_type());
  } else {
    return {ARCHITECTURES::ARCH_NONE, {}};
  }
}


OBJECT_TYPES Header::abstract_object_type(void) const {
  if (obj_macho_to_lief.count(this->file_type()) != 0) {
    return obj_macho_to_lief.at(this->file_type());
  } else {
    return OBJECT_TYPES::TYPE_NONE;
  }
}

ENDIANNESS Header::abstract_endianness(void) const {
  ENDIANNESS e = endi_macho_to_lief.at(this->cpu_type());
  auto not_endianness = [] (ENDIANNESS endian) {
    return endian == ENDIAN_LITTLE ? ENDIAN_BIG : ENDIAN_LITTLE;
  };
  if (this->magic() == MACHO_TYPES::MH_CIGAM or
      this->magic() == MACHO_TYPES::MH_CIGAM_64 or
      this->magic() == MACHO_TYPES::FAT_CIGAM) {
    return not_endianness(e);
  }
  return e;
}


std::set<HEADER_FLAGS> Header::flags_list(void) const {
  std::set<HEADER_FLAGS> flags;

  std::copy_if(
      std::begin(header_flags_array),
      std::end(header_flags_array),
      std::inserter(flags, std::begin(flags)),
      std::bind(&Header::has, this, std::placeholders::_1));

  return flags;
}


bool Header::has(HEADER_FLAGS flag) const {
  return (this->flags() & static_cast<uint32_t>(flag)) > 0;
}


void Header::add(HEADER_FLAGS flag) {
  this->flags(this->flags() | static_cast<uint32_t>(flag));
}

void Header::remove(HEADER_FLAGS flag) {
  this->flags(this->flags() & ~static_cast<uint32_t>(flag));
}


void Header::magic(MACHO_TYPES magic) {
  this->magic_ = magic;
}
void Header::cpu_type(CPU_TYPES cputype) {
  this->cputype_ = cputype;
}

void Header::cpu_subtype(uint32_t cpusubtype) {
  this->cpusubtype_ = cpusubtype;
}

void Header::file_type(FILE_TYPES filetype) {
  this->filetype_ = filetype;
}

void Header::nb_cmds(uint32_t ncmds) {
  this->ncmds_ = ncmds;
}

void Header::sizeof_cmds(uint32_t sizeofcmds) {
  this->sizeofcmds_ = sizeofcmds;
}

void Header::flags(uint32_t flags) {
  this->flags_ = flags;
}

void Header::reserved(uint32_t reserved) {
  this->reserved_ = reserved;
}


void Header::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool Header::operator==(const Header& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Header::operator!=(const Header& rhs) const {
  return not (*this == rhs);
}


Header& Header::operator+=(HEADER_FLAGS c) {
  this->add(c);
  return *this;
}

Header& Header::operator-=(HEADER_FLAGS c) {
  this->remove(c);
  return *this;
}


std::ostream& operator<<(std::ostream& os, const Header& hdr) {

  const auto& flags = hdr.flags_list();

 std::string flags_str = std::accumulate(
     std::begin(flags),
     std::end(flags), std::string{},
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
