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

#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/Structures.hpp"
#include "LIEF/MachO/Section.hpp"
#include "LIEF/MachO/Relocation.hpp"
#include "LIEF/MachO/SegmentCommand.hpp"

namespace LIEF {
namespace MachO {

SegmentCommand::SegmentCommand(void) = default;
SegmentCommand& SegmentCommand::operator=(SegmentCommand other) {
  this->swap(other);
  return *this;
}

SegmentCommand::SegmentCommand(const SegmentCommand& other) :
  LoadCommand{other},
  name_{other.name_},
  virtualAddress_{other.virtualAddress_},
  virtualSize_{other.virtualSize_},
  fileOffset_{other.fileOffset_},
  fileSize_{other.fileSize_},
  maxProtection_{other.maxProtection_},
  initProtection_{other.initProtection_},
  nbSections_{other.nbSections_},
  flags_{other.flags_},
  data_{other.data_},
  sections_{},
  relocations_{}
{

  for (Section* section : other.sections_) {
    Section* new_section = new Section{*section};
    new_section->segment_ = this;
    new_section->segment_name_ = this->name();
    this->sections_.push_back(new_section);
  }

  // TODO:
  //for (Relocation* relocation : other.relocations_) {
  //  Relocation* new_relocation = relocation->clone();
  //  //this->relocations_.push_back(new_relocation);
  //}
}


SegmentCommand::~SegmentCommand(void) {
  for (Relocation* reloc : this->relocations_) {
    delete reloc;
  }

  for (Section* section : this->sections_) {
    delete section;
  }
}

SegmentCommand::SegmentCommand(const segment_command_32 *segmentCmd) :
  LoadCommand{LOAD_COMMAND_TYPES::LC_SEGMENT, segmentCmd->cmdsize},
  name_{segmentCmd->segname, sizeof(segmentCmd->segname)},
  virtualAddress_{segmentCmd->vmaddr},
  virtualSize_{segmentCmd->vmsize},
  fileOffset_{segmentCmd->fileoff},
  fileSize_{segmentCmd->filesize},
  maxProtection_{segmentCmd->maxprot},
  initProtection_{segmentCmd->initprot},
  nbSections_{segmentCmd->nsects},
  flags_{segmentCmd->flags},
  sections_{},
  relocations_{}
{
  this->name_ = std::string{this->name_.c_str()};
}

SegmentCommand::SegmentCommand(const segment_command_64 *segmentCmd) :
  LoadCommand{LOAD_COMMAND_TYPES::LC_SEGMENT_64, segmentCmd->cmdsize},
  name_{segmentCmd->segname, sizeof(segmentCmd->segname)},
  virtualAddress_{segmentCmd->vmaddr},
  virtualSize_{segmentCmd->vmsize},
  fileOffset_{segmentCmd->fileoff},
  fileSize_{segmentCmd->filesize},
  maxProtection_{segmentCmd->maxprot},
  initProtection_{segmentCmd->initprot},
  nbSections_{segmentCmd->nsects},
  flags_{segmentCmd->flags},
  sections_{},
  relocations_{}
{
  this->name_ = std::string{this->name_.c_str()};
}

void SegmentCommand::swap(SegmentCommand& other) {
  LoadCommand::swap(other);

  std::swap(this->virtualAddress_, other.virtualAddress_);
  std::swap(this->virtualSize_,    other.virtualSize_);
  std::swap(this->fileOffset_,     other.fileOffset_);
  std::swap(this->fileSize_,       other.fileSize_);
  std::swap(this->maxProtection_,  other.maxProtection_);
  std::swap(this->initProtection_, other.initProtection_);
  std::swap(this->nbSections_,     other.nbSections_);
  std::swap(this->flags_,          other.flags_);
  std::swap(this->data_,           other.data_);
  std::swap(this->sections_,       other.sections_);
  std::swap(this->relocations_,    other.relocations_);
}

SegmentCommand* SegmentCommand::clone(void) const {
  return new SegmentCommand(*this);
}


SegmentCommand::SegmentCommand(const std::string& name, const content_t& content) :
  SegmentCommand{}
{
  this->name(name);
  this->content(std::move(content));
}


SegmentCommand::SegmentCommand(const std::string& name) :
  SegmentCommand{}
{
  this->name(name);
}

const std::string& SegmentCommand::name(void) const {
  return this->name_;
}

uint64_t SegmentCommand::virtual_address(void) const {
  return this->virtualAddress_;
}

uint64_t SegmentCommand::virtual_size(void) const {
  return this->virtualSize_;
}

uint64_t SegmentCommand::file_size(void) const {
  return this->fileSize_;
}

uint64_t SegmentCommand::file_offset(void) const {
  return this->fileOffset_;
}

uint32_t SegmentCommand::max_protection(void) const {
  return this->maxProtection_;
}

uint32_t SegmentCommand::init_protection(void) const {
  return this->initProtection_;
}

uint32_t SegmentCommand::numberof_sections(void) const {
  return this->nbSections_;
}

uint32_t SegmentCommand::flags(void) const {
  return this->flags_;
}

it_sections SegmentCommand::sections(void) {
  return this->sections_;
}


it_const_sections SegmentCommand::sections(void) const {
  return this->sections_;
}


it_relocations SegmentCommand::relocations(void) {
  return this->relocations_;
}

it_const_relocations SegmentCommand::relocations(void) const {
  return this->relocations_;
}

const SegmentCommand::content_t& SegmentCommand::content(void) const {
  return this->data_;
}

void SegmentCommand::name(const std::string& name) {
  this->name_ = name;
}

void SegmentCommand::virtual_address(uint64_t virtualAddress) {
  this->virtualAddress_ = virtualAddress;
}

void SegmentCommand::virtual_size(uint64_t virtualSize) {
  this->virtualSize_ = virtualSize;
}

void SegmentCommand::file_size(uint64_t fileSize) {
  this->fileSize_ = fileSize;
}

void SegmentCommand::file_offset(uint64_t fileOffset) {
  this->fileOffset_ = fileOffset;
}

void SegmentCommand::max_protection(uint32_t maxProtection) {
  this->maxProtection_ = maxProtection;
}

void SegmentCommand::init_protection(uint32_t initProtection) {
  this->initProtection_ = initProtection;
}

void SegmentCommand::numberof_sections(uint32_t nbSections) {
  this->nbSections_ = nbSections;
}

void SegmentCommand::flags(uint32_t flags) {
  this->flags_ = flags;
}


void SegmentCommand::content(const SegmentCommand::content_t& data) {
  this->data_ = data;
}


void SegmentCommand::remove_all_sections(void) {
  this->numberof_sections(0);
  this->sections_ = {};
}

Section& SegmentCommand::add_section(const Section& section) {
  std::unique_ptr<Section> new_section{new Section{section}};

  new_section->segment_ = this;
  new_section->segment_name_ = this->name();

  new_section->size(section.content().size());

  new_section->offset(this->file_offset() + this->file_size());

  if (section.virtual_address() == 0) {
    new_section->virtual_address(this->virtual_address() + new_section->offset());
  }

  this->file_size(this->file_size() + new_section->size());

  const size_t relative_offset = new_section->offset() - this->file_offset();
  if ((relative_offset + new_section->size()) >= this->data_.size()) {
    this->data_.resize(relative_offset + new_section->size());
  }

  const Section::content_t& content = section.content();
  std::move(
      std::begin(content),
      std::end(content),
      std::begin(this->data_) + relative_offset);

  this->file_size(this->data_.size());
  this->sections_.push_back(new_section.release());
  return *this->sections_.back();
}

bool SegmentCommand::has(const Section& section) const {

  auto&& it = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [&section] (const Section* sec) {
        return *sec == section;
      });
  return it != std::end(this->sections_);
}

bool SegmentCommand::has_section(const std::string& section_name) const {
  auto&& it = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [&section_name] (const Section* sec) {
        return sec->name() == section_name;
      });
  return it != std::end(this->sections_);
}


void SegmentCommand::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool SegmentCommand::operator==(const SegmentCommand& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool SegmentCommand::operator!=(const SegmentCommand& rhs) const {
  return not (*this == rhs);
}



std::ostream& SegmentCommand::print(std::ostream& os) const {

  LoadCommand::print(os);
  os << std::hex;
  os << std::left
     << std::setw(15) << this->name()
     << std::setw(15) << this->virtual_address()
     << std::setw(15) << this->virtual_size()
     << std::setw(15) << this->file_offset()
     << std::setw(15) << this->file_size()
     << std::setw(15) << this->max_protection()
     << std::setw(15) << this->init_protection()
     << std::setw(15) << this->numberof_sections()
     << std::setw(15) << this->flags()
     << std::endl;

  os << "Sections in this segment :" << std::endl;
  for (const Section& section : this->sections()) {
    os << "\t" << section << std::endl;
  }

  return os;
}

}
}
