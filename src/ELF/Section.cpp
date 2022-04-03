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
#include <stdexcept>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <functional>
#include <iterator>

#include "LIEF/ELF/Parser.hpp"

#include "logging.hpp"

#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/EnumToString.hpp"

#include "LIEF/ELF/Section.hpp"
#include "LIEF/ELF/Segment.hpp"

#include "ELF/DataHandler/Handler.hpp"
#include "ELF/Structures.hpp"

namespace LIEF {
namespace ELF {

Section::~Section() = default;
Section::Section() = default;

Section::Section(const details::Elf64_Shdr& header) :
  type_{static_cast<ELF_SECTION_TYPES>(header.sh_type)},
  flags_{header.sh_flags},
  original_size_{header.sh_size},
  link_{header.sh_link},
  info_{header.sh_info},
  address_align_{header.sh_addralign},
  entry_size_{header.sh_entsize}
{
  virtual_address_ = header.sh_addr;
  offset_          = header.sh_offset;
  size_            = header.sh_size;
}

Section::Section(const details::Elf32_Shdr& header) :
  type_{static_cast<ELF_SECTION_TYPES>(header.sh_type)},
  flags_{header.sh_flags},
  original_size_{header.sh_size},
  link_{header.sh_link},
  info_{header.sh_info},
  address_align_{header.sh_addralign},
  entry_size_{header.sh_entsize}
{
  virtual_address_ = header.sh_addr;
  offset_          = header.sh_offset;
  size_            = header.sh_size;
}

Section::Section(const std::string& name, ELF_SECTION_TYPES type) :
  LIEF::Section{name},
  type_{type}
{}


Section::Section(const uint8_t *data, ELF_CLASS type)
{
  if (type == ELF_CLASS::ELFCLASS32) {
    *this = {*reinterpret_cast<const details::Elf32_Shdr*>(data)};
  } else if (type == ELF_CLASS::ELFCLASS64) {
    *this = {*reinterpret_cast<const details::Elf64_Shdr*>(data)};
  }
}

Section& Section::operator=(Section other) {
  swap(other);
  return *this;
}

Section::Section(const Section& other) :
  LIEF::Section{other},
  type_{other.type_},
  flags_{other.flags_},
  original_size_{other.original_size_},
  link_{other.link_},
  info_{other.info_},
  address_align_{other.address_align_},
  entry_size_{other.entry_size_},
  is_frame_{other.is_frame_},
  content_c_{other.content_c_}
{
}

void Section::swap(Section& other) {

  std::swap(name_,            other.name_);
  std::swap(virtual_address_, other.virtual_address_);
  std::swap(offset_,          other.offset_);
  std::swap(size_,            other.size_);

  std::swap(type_,           other.type_);
  std::swap(flags_,          other.flags_);
  std::swap(original_size_,  other.original_size_);
  std::swap(link_,           other.link_);
  std::swap(info_,           other.info_);
  std::swap(address_align_,  other.address_align_);
  std::swap(entry_size_,     other.entry_size_);
  std::swap(segments_,       other.segments_);
  std::swap(is_frame_,       other.is_frame_);
  std::swap(datahandler_,    other.datahandler_);
  std::swap(content_c_,      other.content_c_);
}


ELF_SECTION_TYPES Section::type() const {
  return type_;
}

uint64_t Section::flags() const {
  return flags_;
}

bool Section::has(ELF_SECTION_FLAGS flag) const {
  return (flags() & static_cast<uint64_t>(flag)) != 0;
}


bool Section::has(const Segment& segment) const {
  auto it_segment = std::find_if(std::begin(segments_), std::end(segments_),
      [&segment] (Segment* s) {
        return *s == segment;
      });
  return it_segment != std::end(segments_);
}

uint64_t Section::file_offset() const {
  return offset();
}

uint64_t Section::original_size() const {
  return original_size_;
}

uint64_t Section::information() const {
  return info_;
}

uint64_t Section::entry_size() const {
  return entry_size_;
}

uint64_t Section::alignment() const {
  return address_align_;
}

uint64_t Section::size() const {
  return size_;
}

uint64_t Section::offset() const {
  return offset_;
}


void Section::size(uint64_t size) {
  if (datahandler_ != nullptr && !is_frame()) {
    if (auto node = datahandler_->get(file_offset(), this->size(), DataHandler::Node::SECTION)) {
      node->size(size);
    } else {
      if (type() != ELF_SECTION_TYPES::SHT_NOBITS) {
        LIEF_ERR("Node not found. Can't resize the section {}", name());
      }
    }
  }
  size_ = size;
}


void Section::offset(uint64_t offset) {
  if (datahandler_ != nullptr && !is_frame()) {
    if (auto node = datahandler_->get(file_offset(), size(), DataHandler::Node::SECTION)) {
      node->offset(offset);
    } else {
      if (type() != ELF_SECTION_TYPES::SHT_NOBITS) {
        LIEF_WARN("Node not found. Can't change the offset of the section {}", name());
      }
    }
  }
  offset_ = offset;
}

span<const uint8_t> Section::content() const {
  if (size() == 0 || is_frame()) {
    return {};
  }

  if (datahandler_ == nullptr) {
    return content_c_;
  }

  if (size() > Parser::MAX_SECTION_SIZE) {
    return {};
  }

  auto res = datahandler_->get(offset(), size(), DataHandler::Node::SECTION);
  if (!res) {
    if (type() != ELF_SECTION_TYPES::SHT_NOBITS) {
      LIEF_WARN("Section '{}' does not have content", name());
    }
    return {};
  }
  const std::vector<uint8_t>& binary_content = datahandler_->content();
  DataHandler::Node& node = res.value();
  const uint8_t* ptr = binary_content.data() + node.offset();
  return {ptr, ptr + node.size()};
}

uint32_t Section::link() const {
  return link_;
}

std::set<ELF_SECTION_FLAGS> Section::flags_list() const {
  std::set<ELF_SECTION_FLAGS> flags;
  std::copy_if(std::begin(details::section_flags_array), std::end(details::section_flags_array),
               std::inserter(flags, std::begin(flags)),
               [this] (ELF_SECTION_FLAGS f) { return has(f); });

  return flags;
}

void Section::content(const std::vector<uint8_t>& data) {
  if (is_frame()) {
    return;
  }

  if (!data.empty() && type() == ELF_SECTION_TYPES::SHT_NOBITS) {
    LIEF_INFO("You inserted 0x{:x} bytes in section '{}' which has SHT_NOBITS type",
              data.size(), name());
  }

  if (datahandler_ == nullptr) {
    LIEF_DEBUG("Set 0x{:x} bytes in the cache of section '{}'", data.size(), name());
    content_c_ = data;
    size(data.size());
    return;
  }

  LIEF_DEBUG("Set 0x{:x} bytes in the data handler@0x{:x} of section '{}'",
             data.size(), file_offset(), name());


  auto res = datahandler_->get(file_offset(), size(), DataHandler::Node::SECTION);
  if (!res) {
    LIEF_ERR("Can't find the node. The section's content can't be updated");
    return;
  }

  DataHandler::Node& node = res.value();

  std::vector<uint8_t>& binary_content = datahandler_->content();
  datahandler_->reserve(node.offset(), data.size());

  if (node.size() < data.size()) {
    LIEF_INFO("You inserted 0x{:x} bytes in the section '{}' which is 0x{:x} wide",
              data.size(), name(), node.size());
  }

  size(data.size());

  std::copy(std::begin(data), std::end(data),
            std::begin(binary_content) + node.offset());

}


void Section::content(std::vector<uint8_t>&& data) {
  if (is_frame()) {
    return;
  }
  if (!data.empty() && type() == ELF_SECTION_TYPES::SHT_NOBITS) {
    LIEF_INFO("You inserted 0x{:x} bytes in section '{}' which has SHT_NOBITS type",
              data.size(), name());
  }

  if (datahandler_ == nullptr) {
    LIEF_DEBUG("Set 0x{:x} bytes in the cache of section '{}'", data.size(), name());
    size(data.size());
    content_c_ = std::move(data);
    return;
  }

  LIEF_DEBUG("Set 0x{:x} bytes in the data handler@0x{:x} of section '{}'",
             data.size(), file_offset(), name());

  auto res = datahandler_->get(file_offset(), size(), DataHandler::Node::SECTION);
  if (!res) {
    LIEF_ERR("Can't find the node. The section's content can't be updated");
    return;
  }
  DataHandler::Node& node = res.value();

  std::vector<uint8_t>& binary_content = datahandler_->content();
  datahandler_->reserve(node.offset(), data.size());

  if (node.size() < data.size()) {
    LIEF_INFO("You inserted 0x{:x} bytes in the section '{}' which is 0x{:x} wide",
              data.size(), name(), node.size());
  }

  size(data.size());

  std::move(std::begin(data), std::end(data),
            std::begin(binary_content) + node.offset());
}

void Section::type(ELF_SECTION_TYPES type) {
  type_ = type;
}

void Section::flags(uint64_t flags) {
  flags_ = flags;
}

void Section::add(ELF_SECTION_FLAGS flag) {
  flags(flags() | static_cast<uint64_t>(flag));
}

void Section::remove(ELF_SECTION_FLAGS flag) {
  flags(flags() & (~ static_cast<uint64_t>(flag)));
}

void Section::clear_flags() {
  flags(0);
}

void Section::file_offset(uint64_t offset) {
  this->offset(offset);
}

void Section::link(uint32_t link) {
  link_ = link;
}

void Section::information(uint32_t info) {
  info_ = info;
}

void Section::alignment(uint64_t alignment) {
  address_align_ = alignment;
}

void Section::entry_size(uint64_t entry_size) {
  entry_size_ = entry_size;
}


Section::it_segments Section::segments() {
  return segments_;
}

Section::it_const_segments Section::segments() const {
  return segments_;
}


Section& Section::clear(uint8_t value) {
  if (is_frame()) {
    return *this;
  }
  if (datahandler_ == nullptr) {
    std::fill(std::begin(content_c_), std::end(content_c_), value);
    return *this;
  }

  std::vector<uint8_t>& binary_content = datahandler_->content();
  auto res = datahandler_->get(file_offset(), size(), DataHandler::Node::SECTION);
  if (!res) {
    LIEF_ERR("Can't find the node. The section's content can't be cleared");
    return *this;
  }
  DataHandler::Node& node = res.value();

  std::fill_n(std::begin(binary_content) + node.offset(), size(), value);
  return *this;

}

void Section::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


Section& Section::operator+=(ELF_SECTION_FLAGS c) {
  add(c);
  return *this;
}

Section& Section::operator-=(ELF_SECTION_FLAGS c) {
  remove(c);
  return *this;
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


span<uint8_t> Section::writable_content() {
  if (is_frame()) {
    return {};
  }
  span<const uint8_t> ref = static_cast<const Section*>(this)->content();
  return {const_cast<uint8_t*>(ref.data()), ref.size()};
}


std::ostream& operator<<(std::ostream& os, const Section& section) {
  const auto& flags = section.flags_list();
  std::string flags_str = std::accumulate(
     std::begin(flags), std::end(flags), std::string{},
     [] (const std::string& a, ELF_SECTION_FLAGS b) {
         return a.empty() ? to_string(b) : a + " " + to_string(b);
     });

  Section::it_const_segments segments = section.segments();
  std::string segments_str = std::accumulate(
     std::begin(segments), std::end(segments), std::string{},
     [] (const std::string& a, const Segment& segment) {
         return a.empty() ? to_string(segment.type()) : a + " " + to_string(segment.type());
     });

  os << std::hex;
  os << std::left
     << std::setw(20) << section.name()
     << std::setw(15) << to_string(section.type())
     << std::setw(10) << section.virtual_address()
     << std::setw(10) << section.size()
     << std::setw(10) << section.file_offset()
     << std::setw(10) << section.entropy()
     << std::setw(30) << flags_str
     << std::setw(15) << segments_str;

  return os;
}
}
}
