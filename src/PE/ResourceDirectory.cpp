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

#include "LIEF/PE/hash.hpp"

#include "LIEF/PE/ResourceDirectory.hpp"

namespace LIEF {
namespace PE {


ResourceDirectory::~ResourceDirectory(void) = default;

ResourceDirectory& ResourceDirectory::operator=(ResourceDirectory other) {
  this->swap(other);
  return *this;

}

ResourceDirectory::ResourceDirectory(const ResourceDirectory& other) :
  ResourceNode{static_cast<const ResourceNode&>(other)},
  characteristics_{other.characteristics_},
  timeDateStamp_{other.timeDateStamp_},
  majorVersion_{other.majorVersion_},
  minorVersion_{other.minorVersion_},
  numberOfNameEntries_{other.numberOfNameEntries_},
  numberOfIDEntries_{other.numberOfIDEntries_}
{
}


void ResourceDirectory::swap(ResourceDirectory& other) {
  ResourceNode::swap(other);
  std::swap(this->characteristics_,     other.characteristics_);
  std::swap(this->timeDateStamp_,       other.timeDateStamp_);
  std::swap(this->majorVersion_,        other.majorVersion_);
  std::swap(this->minorVersion_,        other.minorVersion_);
  std::swap(this->numberOfNameEntries_, other.numberOfNameEntries_);
  std::swap(this->numberOfIDEntries_,   other.numberOfIDEntries_);
}

ResourceDirectory::ResourceDirectory(void) :
  ResourceNode{},
  characteristics_{0},
  timeDateStamp_{0},
  majorVersion_{0},
  minorVersion_{0},
  numberOfNameEntries_{0},
  numberOfIDEntries_{0}
{}

ResourceDirectory::ResourceDirectory(const pe_resource_directory_table* header) :
  ResourceNode{},
  characteristics_(header->Characteristics),
  timeDateStamp_(header->TimeDateStamp),
  majorVersion_(header->MajorVersion),
  minorVersion_(header->MajorVersion),
  numberOfNameEntries_(header->NumberOfNameEntries),
  numberOfIDEntries_(header->NumberOfIDEntries)
{}

ResourceDirectory* ResourceDirectory::clone(void) const {
  return new ResourceDirectory{*this};
}


uint32_t ResourceDirectory::characteristics(void) const {
  return this->characteristics_;
}


uint32_t ResourceDirectory::time_date_stamp(void) const {
  return this->timeDateStamp_;
}


uint16_t ResourceDirectory::major_version(void) const {
  return this->majorVersion_;
}


uint16_t ResourceDirectory::minor_version(void) const {
  return this->minorVersion_;
}


uint16_t ResourceDirectory::numberof_name_entries(void) const {
  return this->numberOfNameEntries_;
}


uint16_t ResourceDirectory::numberof_id_entries(void) const {
  return this->numberOfIDEntries_;
}


void ResourceDirectory::characteristics(uint32_t characteristics) {
  this->characteristics_ = characteristics;
}

void ResourceDirectory::time_date_stamp(uint32_t time_date_stamp) {
  this->timeDateStamp_ = time_date_stamp;
}

void ResourceDirectory::major_version(uint16_t major_version) {
  this->majorVersion_ = major_version;
}

void ResourceDirectory::minor_version(uint16_t minor_version) {
  this->minorVersion_ = minor_version;
}

void ResourceDirectory::numberof_name_entries(uint16_t numberof_name_entries) {
  this->numberOfNameEntries_ = numberof_name_entries;
}

void ResourceDirectory::numberof_id_entries(uint16_t numberof_id_entries) {
  this->numberOfIDEntries_ = numberof_id_entries;
}

void ResourceDirectory::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool ResourceDirectory::operator==(const ResourceDirectory& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ResourceDirectory::operator!=(const ResourceDirectory& rhs) const {
  return not (*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const ResourceDirectory& directory) {
  os << static_cast<const ResourceNode&>(directory) << std::endl;
  os << "    " << std::setw(26) << std::left << std::setfill(' ') << "Characteristics :"        << directory.characteristics()       << std::endl;
  os << "    " << std::setw(26) << std::left << std::setfill(' ') << "Time/Date stamp :"        << directory.time_date_stamp()       << std::endl;
  os << "    " << std::setw(26) << std::left << std::setfill(' ') << "Major version :"          << directory.major_version()         << std::endl;
  os << "    " << std::setw(26) << std::left << std::setfill(' ') << "Minor version :"          << directory.minor_version()         << std::endl;
  os << "    " << std::setw(26) << std::left << std::setfill(' ') << "Number of name entries :" << directory.numberof_name_entries() << std::endl;
  os << "    " << std::setw(26) << std::left << std::setfill(' ') << "Number of id entries :"   << directory.numberof_id_entries()   << std::endl;
  return os;
}

}
}
