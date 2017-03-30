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
#include "LIEF/visitors/Hash.hpp"

#include "LIEF/PE/ResourceDirectory.hpp"

namespace LIEF {
namespace PE {


ResourceDirectory::~ResourceDirectory(void) = default;
ResourceDirectory& ResourceDirectory::operator=(const ResourceDirectory&) = default;
ResourceDirectory::ResourceDirectory(const ResourceDirectory&) = default;

ResourceDirectory::ResourceDirectory(void) :
  characteristics_{0},
  timeDateStamp_{0},
  majorVersion_{0},
  minorVersion_{0},
  numberOfNameEntries_{0},
  numberOfIDEntries_{0}
{}

ResourceDirectory::ResourceDirectory(const pe_resource_directory_table* header) :
  characteristics_(header->Characteristics),
  timeDateStamp_(header->TimeDateStamp),
  majorVersion_(header->MajorVersion),
  minorVersion_(header->MajorVersion),
  numberOfNameEntries_(header->NumberOfNameEntries),
  numberOfIDEntries_(header->NumberOfIDEntries)
{
  this->type_ = RESOURCE_NODE_TYPES::DIRECTORY ;
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

void ResourceDirectory::accept(Visitor& visitor) const {
  visitor.visit(this->characteristics());
  visitor.visit(this->time_date_stamp());
  visitor.visit(this->major_version());
  visitor.visit(this->minor_version());
  visitor.visit(this->numberof_name_entries());
  visitor.visit(this->numberof_id_entries());
}

bool ResourceDirectory::operator==(const ResourceDirectory& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ResourceDirectory::operator!=(const ResourceDirectory& rhs) const {
  return not (*this == rhs);
}

}
}
