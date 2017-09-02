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
#include "LIEF/ELF/DynamicEntryRpath.hpp"

#include <iomanip>

namespace LIEF {
namespace ELF {

DynamicEntryRpath::DynamicEntryRpath(void) = default;
DynamicEntryRpath& DynamicEntryRpath::operator=(const DynamicEntryRpath&) = default;
DynamicEntryRpath::DynamicEntryRpath(const DynamicEntryRpath&) = default;

DynamicEntryRpath::DynamicEntryRpath(const Elf64_Dyn* header) :
  DynamicEntry{header}
{}


DynamicEntryRpath::DynamicEntryRpath(const Elf32_Dyn* header) :
  DynamicEntry{header}
{}

DynamicEntryRpath::DynamicEntryRpath(const std::string& rpath) :
  DynamicEntry::DynamicEntry{DYNAMIC_TAGS::DT_RPATH, 0},
  rpath_{rpath}
{
}

const std::string& DynamicEntryRpath::name(void) const {
  return this->rpath_;
}


void DynamicEntryRpath::name(const std::string& name) {
  this->rpath_ = name;
}

const std::string& DynamicEntryRpath::rpath(void) const {
  return this->name();
}


void DynamicEntryRpath::rpath(const std::string& rpath) {
  this->name(rpath);
}

void DynamicEntryRpath::accept(Visitor& visitor) const {
  DynamicEntry::accept(visitor);
  visitor(*this); // Double dispatch to avoid down-casting
  visitor.visit(this->rpath());
}

std::ostream& DynamicEntryRpath::print(std::ostream& os) const {

  DynamicEntry::print(os);
  os << std::hex
     << std::left
     << std::setw(10) << this->rpath();
  return os;

}
}
}



