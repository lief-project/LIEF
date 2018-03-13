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
#include <iomanip>
#include <algorithm>
#include <iterator>

#include "LIEF/logging++.hpp"

#include "LIEF/exception.hpp"

#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/Segment.hpp"
#include "LIEF/ELF/EnumToString.hpp"


namespace LIEF {
namespace ELF {

Segment::~Segment(void) = default;
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
  sections_{},
  datahandler_{nullptr},
  content_c_{other.content()}
{}



Segment::Segment(const Elf64_Phdr* header) :
  type_{static_cast<SEGMENT_TYPES>(header->p_type)},
  flags_{static_cast<ELF_SEGMENT_FLAGS>(header->p_flags)},
  file_offset_{header->p_offset},
  virtual_address_{header->p_vaddr},
  physical_address_{header->p_paddr},
  size_{header->p_filesz},
  virtual_size_{header->p_memsz},
  alignment_{header->p_align},
  sections_{},
  datahandler_{nullptr},
  content_c_{}
{}

Segment::Segment(const Elf32_Phdr* header) :
  type_{static_cast<SEGMENT_TYPES>(header->p_type)},
  flags_{static_cast<ELF_SEGMENT_FLAGS>(header->p_flags)},
  file_offset_{header->p_offset},
  virtual_address_{header->p_vaddr},
  physical_address_{header->p_paddr},
  size_{header->p_filesz},
  virtual_size_{header->p_memsz},
  alignment_{header->p_align},
  sections_{},
  datahandler_{nullptr},
  content_c_{}
{}

Segment::Segment(void) :
  type_{static_cast<SEGMENT_TYPES>(0)},
  flags_{ELF_SEGMENT_FLAGS::PF_NONE},
  file_offset_{0},
  virtual_address_{0},
  physical_address_{0},
  size_{0},
  virtual_size_{0},
  alignment_{0},
  sections_{},
  datahandler_{nullptr},
  content_c_{}
{}

void Segment::swap(Segment& other) {
  std::swap(this->type_,             other.type_);
  std::swap(this->flags_,            other.flags_);
  std::swap(this->file_offset_,      other.file_offset_);
  std::swap(this->virtual_address_,  other.virtual_address_);
  std::swap(this->physical_address_, other.physical_address_);
  std::swap(this->size_,             other.size_);
  std::swap(this->virtual_size_,     other.virtual_size_);
  std::swap(this->alignment_,        other.alignment_);
  std::swap(this->sections_,         other.sections_);
  std::swap(this->datahandler_,      other.datahandler_);
  std::swap(this->content_c_,        other.content_c_);
}


Segment& Segment::operator=(Segment other) {
  this->swap(other);
  return *this;
}


Segment::Segment(const std::vector<uint8_t>& header, ELF_CLASS type) {
  if (type == ELF_CLASS::ELFCLASS32) {
    *this = {reinterpret_cast<const Elf32_Phdr*>(header.data())};
  } else if (type == ELF_CLASS::ELFCLASS64) {
    *this = {reinterpret_cast<const Elf64_Phdr*>(header.data())};
  }
}

Segment::Segment(const std::vector<uint8_t>& header) {
  if (header.size() == sizeof(Elf32_Phdr)) {
    *this = {reinterpret_cast<const Elf32_Phdr*>(header.data())};
  } else if (header.size() == sizeof(Elf64_Phdr)) {
    *this = {reinterpret_cast<const Elf64_Phdr*>(header.data())};
  } else {
    throw LIEF::corrupted("Unable to determine the header type: 32bits or 64bits (Wrong size)");
  }
}

SEGMENT_TYPES Segment::type(void) const {
  return this->type_;
}


ELF_SEGMENT_FLAGS Segment::flags(void) const {
  return this->flags_;
}


uint64_t Segment::file_offset(void) const {
  return this->file_offset_;
}


uint64_t Segment::virtual_address(void) const {
  return this->virtual_address_;
}


uint64_t Segment::physical_address(void) const {
  return this->physical_address_;
}


uint64_t Segment::physical_size(void) const {
  return this->size_;
}


uint64_t Segment::virtual_size(void) const {
  return this->virtual_size_;
}


uint64_t Segment::alignment(void) const {
  return this->alignment_;
}

std::vector<uint8_t> Segment::content(void) const {
  if (this->datahandler_ == nullptr) {
    VLOG(VDEBUG) << "Content from cache";
    return this->content_c_;
  }

  DataHandler::Node& node = this->datahandler_->get(
      this->file_offset(),
      this->physical_size(),
      DataHandler::Node::SEGMENT);
  const std::vector<uint8_t>& binary_content = this->datahandler_->content();
  return {binary_content.data() + node.offset(), binary_content.data() + node.offset() + node.size()};
}


it_const_sections Segment::sections(void) const {
  return {this->sections_};
}


it_sections Segment::sections(void) {
  return {this->sections_};
}

bool Segment::has(ELF_SEGMENT_FLAGS flag) const {
  return ((this->flags() & flag) != ELF_SEGMENT_FLAGS::PF_NONE);
}


bool Segment::has(const Section& section) const {

  auto&& it_section = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [&section] (Section* s) {
        return *s == section;
      });
  return it_section != std::end(this->sections_);
}


bool Segment::has(const std::string& name) const {
  auto&& it_section = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [&name] (Section* s) {
        return s->name() == name;
      });
  return it_section != std::end(this->sections_);
}


void Segment::flags(ELF_SEGMENT_FLAGS flags) {
  this->flags_ = flags;
}


void Segment::add(ELF_SEGMENT_FLAGS flag) {
  this->flags(this->flags() | flag);
}


void Segment::remove(ELF_SEGMENT_FLAGS flag) {
  this->flags(this->flags() & ~flag);
}


void Segment::clear_flags(void) {
  this->flags_ = ELF_SEGMENT_FLAGS::PF_NONE;
}


void Segment::file_offset(uint64_t file_offset) {
  if (this->datahandler_ != nullptr) {
    DataHandler::Node& node = this->datahandler_->get(
        this->file_offset(), this->physical_size(),
        DataHandler::Node::SEGMENT);
    node.offset(file_offset);
  }
  this->file_offset_ = file_offset;
}


void Segment::virtual_address(uint64_t virtualAddress) {
  this->virtual_address_ = virtualAddress;
}


void Segment::physical_address(uint64_t physicalAddress) {
  this->physical_address_ = physicalAddress;
}


void Segment::physical_size(uint64_t physicalSize) {
  if (this->datahandler_ != nullptr) {
    DataHandler::Node& node = this->datahandler_->get(
        this->file_offset(), this->physical_size(),
        DataHandler::Node::SEGMENT);
    node.size(physicalSize);
  }
  this->size_ = physicalSize;
}


void Segment::virtual_size(uint64_t virtualSize) {
  this->virtual_size_ = virtualSize;
}


void Segment::alignment(uint64_t alignment) {
  this->alignment_ = alignment;
}

void Segment::type(SEGMENT_TYPES type) {
  this->type_ = type;
}

void Segment::content(const std::vector<uint8_t>& content) {
  if (this->datahandler_ == nullptr) {
    VLOG(VDEBUG) << "Set content in the cache";
    this->content_c_ = content;

    this->physical_size(content.size());
    return;
  }

  VLOG(VDEBUG) << "Set content in the data handler [0x" << std::hex << this->file_offset() << ", 0x" << content.size() << "]";

  DataHandler::Node& node = this->datahandler_->get(
      this->file_offset(),
      this->physical_size(),
      DataHandler::Node::SEGMENT);

  std::vector<uint8_t>& binary_content = this->datahandler_->content();
  this->datahandler_->reserve(node.offset(), content.size());

  if (node.size() < content.size()) {
    LOG(WARNING) << "You inserted data in segment '"
                 << to_string(this->type()) << "' It may lead to overaly!" << std::endl;
  }

  this->physical_size(node.size());

  std::copy(
      std::begin(content),
      std::end(content),
      std::begin(binary_content) + node.offset());
}


void Segment::content(std::vector<uint8_t>&& content) {
  if (this->datahandler_ == nullptr) {
    VLOG(VDEBUG) << "Set content in the cache";
    this->content_c_ = std::move(content);

    this->physical_size(content.size());
    return;
  }

  VLOG(VDEBUG) << "Set content in the data handler [0x" << std::hex << this->file_offset() << ", 0x" << content.size() << "]";

  DataHandler::Node& node = this->datahandler_->get(
      this->file_offset(),
      this->physical_size(),
      DataHandler::Node::SEGMENT);

  std::vector<uint8_t>& binary_content = this->datahandler_->content();
  this->datahandler_->reserve(node.offset(), content.size());

  if (node.size() < content.size()) {
    LOG(WARNING) << "You inserted data in segment '"
                 << to_string(this->type()) << "' It may lead to overaly!" << std::endl;
  }

  this->physical_size(node.size());

  std::move(
      std::begin(content),
      std::end(content),
      std::begin(binary_content) + node.offset());
}

void Segment::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


Segment& Segment::operator+=(ELF_SEGMENT_FLAGS c) {
  this->add(c);
  return *this;
}

Segment& Segment::operator-=(ELF_SEGMENT_FLAGS c) {
  this->remove(c);
  return *this;
}

bool Segment::operator==(const Segment& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Segment::operator!=(const Segment& rhs) const {
  return not (*this == rhs);
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
