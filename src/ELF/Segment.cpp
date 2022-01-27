/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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
#include <iomanip>
#include <algorithm>
#include <iterator>

#include "logging.hpp"

#include "LIEF/exception.hpp"

#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/Segment.hpp"
#include "LIEF/ELF/EnumToString.hpp"

#include "LIEF/ELF/DataHandler/Handler.hpp"
#include "LIEF/ELF/Section.hpp"


namespace LIEF {
namespace ELF {

Segment::~Segment() = default;
Segment::Segment(const Segment& other) :
  Object{other},
  type_{other.type_},
  flags_{other.flags_},
  file_offset_{other.file_offset_},
  virtual_address_{other.virtual_address_},
  physical_address_{other.physical_address_},
  size_{other.size_},
  virtual_size_{other.virtual_size_},
  alignment_{other.alignment_},
  content_c_{other.content()}
{}



Segment::Segment(const details::Elf64_Phdr& header) :
  type_{static_cast<SEGMENT_TYPES>(header.p_type)},
  flags_{static_cast<ELF_SEGMENT_FLAGS>(header.p_flags)},
  file_offset_{header.p_offset},
  virtual_address_{header.p_vaddr},
  physical_address_{header.p_paddr},
  size_{header.p_filesz},
  virtual_size_{header.p_memsz},
  alignment_{header.p_align}
{}

Segment::Segment(const details::Elf32_Phdr& header) :
  type_{static_cast<SEGMENT_TYPES>(header.p_type)},
  flags_{static_cast<ELF_SEGMENT_FLAGS>(header.p_flags)},
  file_offset_{header.p_offset},
  virtual_address_{header.p_vaddr},
  physical_address_{header.p_paddr},
  size_{header.p_filesz},
  virtual_size_{header.p_memsz},
  alignment_{header.p_align}
{}

Segment::Segment() :
  type_{static_cast<SEGMENT_TYPES>(0)},
  flags_{ELF_SEGMENT_FLAGS::PF_NONE},
  file_offset_{0},
  virtual_address_{0},
  physical_address_{0},
  size_{0},
  virtual_size_{0},
  alignment_{0}
{}

void Segment::swap(Segment& other) {
  std::swap(type_,             other.type_);
  std::swap(flags_,            other.flags_);
  std::swap(file_offset_,      other.file_offset_);
  std::swap(virtual_address_,  other.virtual_address_);
  std::swap(physical_address_, other.physical_address_);
  std::swap(size_,             other.size_);
  std::swap(virtual_size_,     other.virtual_size_);
  std::swap(alignment_,        other.alignment_);
  std::swap(sections_,         other.sections_);
  std::swap(datahandler_,      other.datahandler_);
  std::swap(content_c_,        other.content_c_);
}


Segment& Segment::operator=(Segment other) {
  swap(other);
  return *this;
}


Segment::Segment(const std::vector<uint8_t>& header, ELF_CLASS type) {
  if (type == ELF_CLASS::ELFCLASS32) {
    *this = {*reinterpret_cast<const details::Elf32_Phdr*>(header.data())};
  } else if (type == ELF_CLASS::ELFCLASS64) {
    *this = {*reinterpret_cast<const details::Elf64_Phdr*>(header.data())};
  }
}

Segment::Segment(const std::vector<uint8_t>& header) {
  if (header.size() == sizeof(details::Elf32_Phdr)) {
    *this = {*reinterpret_cast<const details::Elf32_Phdr*>(header.data())};
  } else if (header.size() == sizeof(details::Elf64_Phdr)) {
    *this = {*reinterpret_cast<const details::Elf64_Phdr*>(header.data())};
  } else {
    throw LIEF::corrupted("Unable to determine the header type: 32bits or 64bits (Wrong size)");
  }
}

SEGMENT_TYPES Segment::type() const {
  return type_;
}


ELF_SEGMENT_FLAGS Segment::flags() const {
  return flags_;
}


uint64_t Segment::file_offset() const {
  return file_offset_;
}


uint64_t Segment::virtual_address() const {
  return virtual_address_;
}


uint64_t Segment::physical_address() const {
  return physical_address_;
}


uint64_t Segment::physical_size() const {
  return size_;
}


uint64_t Segment::virtual_size() const {
  return virtual_size_;
}


uint64_t Segment::alignment() const {
  return alignment_;
}

std::vector<uint8_t> Segment::content() const {
  if (datahandler_ == nullptr) {
    LIEF_DEBUG("Get content of segment {}@0x{:x} from cache",
        to_string(type()), virtual_address());
    return content_c_;
  }

  DataHandler::Node& node = datahandler_->get(
      file_offset(),
      physical_size(),
      DataHandler::Node::SEGMENT);

  const std::vector<uint8_t>& binary_content = datahandler_->content();
  const size_t size = binary_content.size();
  if (node.offset() >= size || (node.offset() + node.size()) >= size) {
    LIEF_ERR("Corrupted data");
    return {};
  }

  return {binary_content.data() + node.offset(), binary_content.data() + node.offset() + node.size()};
}

size_t Segment::get_content_size() const {
  DataHandler::Node& node = datahandler_->get(
      file_offset(),
      physical_size(),
      DataHandler::Node::SEGMENT);
  return node.size();
}
template<typename T> T Segment::get_content_value(size_t offset) const {
  T ret;
  if (datahandler_ == nullptr) {
    LIEF_DEBUG("Get content of segment {}@0x{:x} from cache",
        to_string(type()), virtual_address());
    memcpy(&ret, content_c_.data() + offset, sizeof(T));
  } else {
    DataHandler::Node& node = datahandler_->get(
        file_offset(),
        physical_size(),
        DataHandler::Node::SEGMENT);
    const std::vector<uint8_t>& binary_content = datahandler_->content();
    memcpy(&ret, binary_content.data() + node.offset() + offset, sizeof(T));
  }
  return ret;
}

template unsigned short Segment::get_content_value<unsigned short>(size_t offset) const;
template unsigned int Segment::get_content_value<unsigned int>(size_t offset) const;
template unsigned long Segment::get_content_value<unsigned long>(size_t offset) const;
template unsigned long long Segment::get_content_value<unsigned long long>(size_t offset) const;

template<typename T> void Segment::set_content_value(size_t offset, T value) {
  if (datahandler_ == nullptr) {
    LIEF_DEBUG("Set content of segment {}@0x{:x}:0x{:x} in cache (0x{:x} bytes)",
        to_string(type()), virtual_address(), offset, sizeof(T));
    if (offset + sizeof(T) > content_c_.size()) {
      content_c_.resize(offset + sizeof(T));
      physical_size(offset + sizeof(T));
    }
    memcpy(content_c_.data() + offset, &value, sizeof(T));
  } else {
    DataHandler::Node& node = datahandler_->get(
        file_offset(),
        physical_size(),
        DataHandler::Node::SEGMENT);
    std::vector<uint8_t>& binary_content = datahandler_->content();

    if (offset + sizeof(T) > binary_content.size()) {
      datahandler_->reserve(node.offset(), offset + sizeof(T));

      LIEF_INFO("You up to bytes in the segment {}@0x{:x} which is 0x{:x} wide",
        offset + sizeof(T), to_string(type()), virtual_size(), binary_content.size());
    }
    physical_size(node.size());
    memcpy(binary_content.data() + node.offset() + offset, &value, sizeof(T));
  }
}
template void Segment::set_content_value<unsigned short>(size_t offset, unsigned short value);
template void Segment::set_content_value<unsigned int>(size_t offset, unsigned int value);
template void Segment::set_content_value<unsigned long>(size_t offset, unsigned long value);
template void Segment::set_content_value<unsigned long long>(size_t offset, unsigned long long value);

it_const_sections Segment::sections() const {
  return {sections_};
}


it_sections Segment::sections() {
  return {sections_};
}

bool Segment::has(ELF_SEGMENT_FLAGS flag) const {
  return ((flags() & flag) != ELF_SEGMENT_FLAGS::PF_NONE);
}


bool Segment::has(const Section& section) const {
  auto it_section = std::find_if(std::begin(sections_), std::end(sections_),
      [&section] (Section* s) {
        return *s == section;
      });
  return it_section != std::end(sections_);
}


bool Segment::has(const std::string& name) const {
  auto it_section = std::find_if(std::begin(sections_), std::end(sections_),
      [&name] (Section* s) {
        return s->name() == name;
      });
  return it_section != std::end(sections_);
}


void Segment::flags(ELF_SEGMENT_FLAGS flags) {
  flags_ = flags;
}


void Segment::add(ELF_SEGMENT_FLAGS flag) {
  flags(flags() | flag);
}


void Segment::remove(ELF_SEGMENT_FLAGS flag) {
  flags(flags() & ~flag);
}


void Segment::clear_flags() {
  flags_ = ELF_SEGMENT_FLAGS::PF_NONE;
}


void Segment::file_offset(uint64_t file_offset) {
  if (datahandler_ != nullptr) {
    DataHandler::Node& node = datahandler_->get(
        this->file_offset(), physical_size(),
        DataHandler::Node::SEGMENT);
    node.offset(file_offset);
  }
  file_offset_ = file_offset;
}


void Segment::virtual_address(uint64_t virtual_address) {
  virtual_address_ = virtual_address;
}


void Segment::physical_address(uint64_t physical_address) {
  physical_address_ = physical_address;
}


void Segment::physical_size(uint64_t physical_size) {
  if (datahandler_ != nullptr) {
    DataHandler::Node& node = datahandler_->get(
        file_offset(), this->physical_size(),
        DataHandler::Node::SEGMENT);
    node.size(physical_size);
  }
  size_ = physical_size;
}


void Segment::virtual_size(uint64_t virtual_size) {
  virtual_size_ = virtual_size;
}


void Segment::alignment(uint64_t alignment) {
  alignment_ = alignment;
}

void Segment::type(SEGMENT_TYPES type) {
  type_ = type;
}

void Segment::content(const std::vector<uint8_t>& content) {
  if (datahandler_ == nullptr) {
    LIEF_DEBUG("Set content of segment {}@0x{:x} in cache (0x{:x} bytes)",
        to_string(type()), virtual_address(), content.size());
    content_c_ = content;

    physical_size(content.size());
    return;
  }

  LIEF_DEBUG("Set content of segment {}@0x{:x} in data handler @0x{:x} (0x{:x} bytes)",
      to_string(type()), virtual_address(), file_offset(), content.size());

  DataHandler::Node& node = datahandler_->get(
      file_offset(),
      physical_size(),
      DataHandler::Node::SEGMENT);

  std::vector<uint8_t>& binary_content = datahandler_->content();
  datahandler_->reserve(node.offset(), content.size());

  if (node.size() < content.size()) {
      LIEF_INFO("You inserted 0x{:x} bytes in the segment {}@0x{:x} which is 0x{:x} wide",
        content.size(), to_string(type()), virtual_size(), node.size());
  }

  physical_size(node.size());

  std::copy(
      std::begin(content),
      std::end(content),
      std::begin(binary_content) + node.offset());
}


void Segment::content(std::vector<uint8_t>&& content) {
  if (datahandler_ == nullptr) {
    LIEF_DEBUG("Set content of segment {}@0x{:x} in cache (0x{:x} bytes)",
        to_string(type()), virtual_address(), content.size());
    physical_size(content.size());
    content_c_ = std::move(content);
    return;
  }

  LIEF_DEBUG("Set content of segment {}@0x{:x} in data handler @0x{:x} (0x{:x} bytes)",
      to_string(type()), virtual_address(), file_offset(), content.size());

  DataHandler::Node& node = datahandler_->get(
      file_offset(),
      physical_size(),
      DataHandler::Node::SEGMENT);

  std::vector<uint8_t>& binary_content = datahandler_->content();
  datahandler_->reserve(node.offset(), content.size());

  if (node.size() < content.size()) {
      LIEF_INFO("You inserted 0x{:x} bytes in the segment {}@0x{:x} which is 0x{:x} wide",
        content.size(), to_string(type()), virtual_size(), node.size());
  }

  physical_size(node.size());

  std::move(
      std::begin(content),
      std::end(content),
      std::begin(binary_content) + node.offset());
}

void Segment::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


Segment& Segment::operator+=(ELF_SEGMENT_FLAGS flag) {
  add(flag);
  return *this;
}

Segment& Segment::operator-=(ELF_SEGMENT_FLAGS flag) {
  remove(flag);
  return *this;
}

bool Segment::operator==(const Segment& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Segment::operator!=(const Segment& rhs) const {
  return !(*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const ELF::Segment& segment) {


  std::string flags = "---";

  if (segment.has(ELF_SEGMENT_FLAGS::PF_R)) {
    flags[0] = 'r';
  }

  if (segment.has(ELF_SEGMENT_FLAGS::PF_W)) {
    flags[1] = 'w';
  }

  if (segment.has(ELF_SEGMENT_FLAGS::PF_X)) {
    flags[2] = 'x';
  }

  os << std::hex;
  os << std::left
     << std::setw(18) << to_string(segment.type())
     << std::setw(10) << flags
     << std::setw(10) << segment.file_offset()
     << std::setw(10) << segment.virtual_address()
     << std::setw(10) << segment.physical_address()
     << std::setw(10) << segment.physical_size()
     << std::setw(10) << segment.virtual_size()
     << std::setw(10) << segment.alignment()
     << std::endl;

  if (segment.sections().size() > 0) {
    os << "Sections in this segment :" << std::endl;
    for (const Section& section : segment.sections()) {
      os << "\t" << section.name() << std::endl;
    }
  }
  return os;
}
}
}
