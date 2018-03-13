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

#include "LIEF/MachO/SegmentCommand.hpp"

namespace LIEF {
namespace MachO {

SegmentCommand::SegmentCommand(void) = default;
SegmentCommand& SegmentCommand::operator=(const SegmentCommand&) = default;
SegmentCommand::SegmentCommand(const SegmentCommand&) = default;
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
  relocations_{}
{
  this->name_ = std::string{this->name_.c_str()};
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

const std::vector<uint8_t>& SegmentCommand::content(void) const {
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


//void SegmentCommand::add_section(const Section& section) {
//  this->sections_.push_back(section);
//}

void SegmentCommand::content(const std::vector<uint8_t>& data) {
  this->data_ = data;
}


void SegmentCommand::remove_all_sections(void) {
  this->numberof_sections(0);
  this->sections_ = {};
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
