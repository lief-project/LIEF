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
#include <algorithm>
#include <numeric>
#include <iomanip>
#include <iterator>

#include "logging.hpp"
#include "LIEF/exception.hpp"
#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/Section.hpp"
#include "LIEF/MachO/Relocation.hpp"
#include "LIEF/MachO/SegmentCommand.hpp"
#include "LIEF/MachO/EnumToString.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

Section::Section() = default;
Section::~Section() = default;

Section& Section::operator=(Section other) {
  swap(other);
  return *this;
}

Section::Section(const Section& other) :
  LIEF::Section{other},
  segment_name_{other.segment_name_},
  original_size_{other.original_size_},
  align_{other.align_},
  relocations_offset_{other.relocations_offset_},
  nbof_relocations_{other.nbof_relocations_},
  flags_{other.flags_},
  reserved1_{other.reserved1_},
  reserved2_{other.reserved2_},
  reserved3_{other.reserved3_},
  content_{other.content_}
{}




Section::Section(const details::section_32& sec) :
  segment_name_{sec.segname, sizeof(sec.sectname)},
  original_size_{sec.size},
  align_{sec.align},
  relocations_offset_{sec.reloff},
  nbof_relocations_{sec.nreloc},
  flags_{sec.flags},
  reserved1_{sec.reserved1},
  reserved2_{sec.reserved2}
{
  name_            = {sec.sectname, sizeof(sec.sectname)};
  size_            = sec.size;
  offset_          = sec.offset;
  virtual_address_ = sec.addr;

  name_         = name_.c_str();
  segment_name_ = segment_name_.c_str();
}

Section::Section(const details::section_64& sec) :
  segment_name_{sec.segname, sizeof(sec.segname)},
  original_size_{sec.size},
  align_{sec.align},
  relocations_offset_{sec.reloff},
  nbof_relocations_{sec.nreloc},
  flags_{sec.flags},
  reserved1_{sec.reserved1},
  reserved2_{sec.reserved2},
  reserved3_{sec.reserved3}
{
  name_            = {sec.sectname, sizeof(sec.sectname)};
  size_            = sec.size;
  offset_          = sec.offset;
  virtual_address_ = sec.addr;

  name_         = name_.c_str();
  segment_name_ = segment_name_.c_str();
}


void Section::swap(Section& other) {
  std::swap(name_,            other.name_);
  std::swap(virtual_address_, other.virtual_address_);
  std::swap(size_,            other.size_);
  std::swap(offset_,          other.offset_);

  std::swap(segment_name_,        other.segment_name_);
  std::swap(original_size_,       other.original_size_);
  std::swap(align_,               other.align_);
  std::swap(relocations_offset_,  other.relocations_offset_);
  std::swap(nbof_relocations_,    other.nbof_relocations_);
  std::swap(flags_,               other.flags_);
  std::swap(reserved1_,           other.reserved1_);
  std::swap(reserved2_,           other.reserved2_);
  std::swap(reserved3_,           other.reserved3_);
  std::swap(content_,             other.content_);
  std::swap(segment_,             other.segment_);
  std::swap(relocations_,         other.relocations_);

}


Section::Section(std::string name) {
  this->name(std::move(name));
}

Section::Section(std::string name, Section::content_t content) {
  this->name(std::move(name));
  this->content(std::move(content));
}

span<const uint8_t> Section::content() const {
  if (segment_ == nullptr) {
    return content_;
  }

  if (size_ == 0 || offset_ == 0) { // bss section for instance
    return {};
  }

  uint64_t relative_offset = offset_ - segment_->file_offset();
  span<const uint8_t> content = segment_->content();
  if (relative_offset > content.size() || (relative_offset + size_) > content.size()) {
    LIEF_ERR("Section's size is bigger than segment's size");
    return {};
  }
  return content.subspan(relative_offset, size_);
}

void Section::content(const Section::content_t& data) {
  if (segment_ == nullptr) {
    content_ = data;
    return;
  }

  if (size_ == 0 || offset_ == 0) { // bss section for instance
    LIEF_ERR("Offset or size is null");
    return;
  }

  uint64_t relative_offset = offset_ - segment_->file_offset();

  span<uint8_t> content = segment_->writable_content();

  if (relative_offset > content.size() || (relative_offset + data.size()) > content.size()) {
    LIEF_ERR("New data are bigger than the original one");
    return;
  }

  std::move(std::begin(data), std::end(data),
            content.data() + relative_offset);
}

const std::string& Section::segment_name() const {
  if (segment_ == nullptr || segment_->name().empty()) {
    return segment_name_;
  }
  return segment_->name();
}

uint64_t Section::address() const {
  return virtual_address();
}

uint32_t Section::alignment() const {
  return align_;
}

uint32_t Section::relocation_offset() const {
  return relocations_offset_;
}

uint32_t Section::numberof_relocations() const {
  return nbof_relocations_;
}

uint32_t Section::flags() const {
  static constexpr size_t SECTION_FLAGS_MASK = 0xffffff00u;
  return (flags_ & SECTION_FLAGS_MASK);
}

uint32_t Section::reserved1() const {
  return reserved1_;
}

uint32_t Section::reserved2() const {
  return reserved2_;
}

uint32_t Section::reserved3() const {
  return reserved3_;
}


uint32_t Section::raw_flags() const {
  return flags_;
}

Section::it_relocations Section::relocations() {
  return relocations_;
}

Section::it_const_relocations Section::relocations() const {
  return relocations_;
}

MACHO_SECTION_TYPES Section::type() const {
  static constexpr size_t SECTION_TYPE_MASK = 0xFF;
  return static_cast<MACHO_SECTION_TYPES>(flags_ & SECTION_TYPE_MASK);
}

Section::flag_list_t Section::flags_list() const {

  Section::flag_list_t flags;

  std::copy_if(
      std::begin(section_flags_array), std::end(section_flags_array),
      std::inserter(flags, std::begin(flags)),
      [this] (MACHO_SECTION_FLAGS f) { return has(f); });

  return flags;
}

void Section::segment_name(const std::string& name) {
  segment_name_ = name;
  if (segment_ != nullptr && !segment_->name().empty()) {
    segment_->name(name);
  }
}

void Section::address(uint64_t address) {
  virtual_address(address);
}

void Section::alignment(uint32_t align) {
  align_ = align;
}

void Section::relocation_offset(uint32_t relocOffset) {
  relocations_offset_ = relocOffset;
}

void Section::numberof_relocations(uint32_t nbReloc) {
  nbof_relocations_ = nbReloc;
}

void Section::flags(uint32_t flags) {
  flags_ = flags_ | flags;
}

void Section::reserved1(uint32_t reserved1) {
  reserved1_ = reserved1;
}

void Section::reserved2(uint32_t reserved2) {
  reserved2_ = reserved2;
}

void Section::reserved3(uint32_t reserved3) {
  reserved3_ = reserved3;
}

void Section::type(MACHO_SECTION_TYPES type) {
  static constexpr size_t SECTION_FLAGS_MASK = 0xffffff00u;
  flags_ = (flags_ & SECTION_FLAGS_MASK) | static_cast<uint8_t>(type);
}


bool Section::has(MACHO_SECTION_FLAGS flag) const {
  return (static_cast<uint32_t>(flag) & flags()) > 0;
}

void Section::add(MACHO_SECTION_FLAGS flag) {
  flags(raw_flags() | static_cast<uint32_t>(flag));
}

void Section::remove(MACHO_SECTION_FLAGS flag) {
  flags_= raw_flags() & (~ static_cast<uint32_t>(flag));
}

Section& Section::operator+=(MACHO_SECTION_FLAGS flag) {
  add(flag);
  return *this;
}

Section& Section::operator-=(MACHO_SECTION_FLAGS flag) {
  remove(flag);
  return *this;
}


void Section::clear(uint8_t v) {
  Section::content_t clear(size(), v);
  content(std::move(clear));
}


bool Section::has_segment() const {
  return segment_ != nullptr;
}

SegmentCommand* Section::segment() {
  return const_cast<SegmentCommand*>(static_cast<const Section*>(this)->segment());
}

const SegmentCommand* Section::segment() const {
  return segment_;
}


void Section::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool Section::operator==(const Section& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Section::operator!=(const Section& rhs) const {
  return !(*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const Section& section) {
  const auto& flags = section.flags_list();

   std::string flags_str = std::accumulate(
     std::begin(flags),
     std::end(flags), std::string{},
     [] (const std::string& a, MACHO_SECTION_FLAGS b) {
         return a.empty() ? to_string(b) : a + " " + to_string(b);
     });

  os << std::hex;
  os << std::left
     << std::setw(17) << section.name()
     << std::setw(17) << section.segment_name()
     << std::setw(10) << section.address()
     << std::setw(10) << section.size()
     << std::setw(10) << section.offset()
     << std::setw(10) << section.alignment()
     << std::setw(30) << to_string(section.type())
     << std::setw(20) << section.relocation_offset()
     << std::setw(20) << section.numberof_relocations()
     << std::setw(10) << section.reserved1()
     << std::setw(10) << section.reserved2()
     << std::setw(10) << section.reserved3()
     << std::setw(10) << flags_str;

  if (section.segment_ != nullptr) {
    //os << std::setw(10) << section.segment_->name();
  }

  if (section.relocations().size() > 0)  {
    os << std::endl;
    os << "Relocations associated with the section :" << std::endl;
    for (const Relocation& relocation : section.relocations()) {
      os << "    " << relocation << std::endl;
    }
  }


  return os;
}

} // namespace MachO
} // namespace LIEF
