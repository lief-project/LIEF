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
#include <iomanip>

#include "LIEF/PE/hash.hpp"

#include "LIEF/PE/ResourceDirectory.hpp"
#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {


ResourceDirectory::~ResourceDirectory() = default;

ResourceDirectory& ResourceDirectory::operator=(ResourceDirectory other) {
  swap(other);
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
  std::swap(characteristics_,     other.characteristics_);
  std::swap(timeDateStamp_,       other.timeDateStamp_);
  std::swap(majorVersion_,        other.majorVersion_);
  std::swap(minorVersion_,        other.minorVersion_);
  std::swap(numberOfNameEntries_, other.numberOfNameEntries_);
  std::swap(numberOfIDEntries_,   other.numberOfIDEntries_);
}

ResourceDirectory::ResourceDirectory() {
  type_ = ResourceNode::TYPE::DIRECTORY;
}

ResourceDirectory::ResourceDirectory(const details::pe_resource_directory_table& header) :
  characteristics_(header.Characteristics),
  timeDateStamp_(header.TimeDateStamp),
  majorVersion_(header.MajorVersion),
  minorVersion_(header.MajorVersion),
  numberOfNameEntries_(header.NumberOfNameEntries),
  numberOfIDEntries_(header.NumberOfIDEntries)
{
  type_ = ResourceNode::TYPE::DIRECTORY;
}

ResourceDirectory* ResourceDirectory::clone() const {
  return new ResourceDirectory{*this};
}


uint32_t ResourceDirectory::characteristics() const {
  return characteristics_;
}


uint32_t ResourceDirectory::time_date_stamp() const {
  return timeDateStamp_;
}


uint16_t ResourceDirectory::major_version() const {
  return majorVersion_;
}


uint16_t ResourceDirectory::minor_version() const {
  return minorVersion_;
}


uint16_t ResourceDirectory::numberof_name_entries() const {
  return numberOfNameEntries_;
}


uint16_t ResourceDirectory::numberof_id_entries() const {
  return numberOfIDEntries_;
}


void ResourceDirectory::characteristics(uint32_t characteristics) {
  characteristics_ = characteristics;
}

void ResourceDirectory::time_date_stamp(uint32_t time_date_stamp) {
  timeDateStamp_ = time_date_stamp;
}

void ResourceDirectory::major_version(uint16_t major_version) {
  majorVersion_ = major_version;
}

void ResourceDirectory::minor_version(uint16_t minor_version) {
  minorVersion_ = minor_version;
}

void ResourceDirectory::numberof_name_entries(uint16_t numberof_name_entries) {
  numberOfNameEntries_ = numberof_name_entries;
}

void ResourceDirectory::numberof_id_entries(uint16_t numberof_id_entries) {
  numberOfIDEntries_ = numberof_id_entries;
}

void ResourceDirectory::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool ResourceDirectory::operator==(const ResourceDirectory& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ResourceDirectory::operator!=(const ResourceDirectory& rhs) const {
  return !(*this == rhs);
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
