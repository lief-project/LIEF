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
#include "LIEF/ELF/DynamicEntryRunPath.hpp"

#include <iomanip>

namespace LIEF {
namespace ELF {

DynamicEntryRunPath::DynamicEntryRunPath(void) = default;
DynamicEntryRunPath& DynamicEntryRunPath::operator=(const DynamicEntryRunPath&) = default;
DynamicEntryRunPath::DynamicEntryRunPath(const DynamicEntryRunPath&) = default;

DynamicEntryRunPath::DynamicEntryRunPath(const Elf64_Dyn* header) :
  DynamicEntry{header}
{}


DynamicEntryRunPath::DynamicEntryRunPath(const Elf32_Dyn* header) :
  DynamicEntry{header}
{}

DynamicEntryRunPath::DynamicEntryRunPath(const std::string& runpath) :
  DynamicEntry::DynamicEntry{DYNAMIC_TAGS::DT_RUNPATH, 0},
  runpath_{runpath}
{
}

const std::string& DynamicEntryRunPath::name(void) const {
  return this->runpath_;
}


void DynamicEntryRunPath::name(const std::string& name) {
  this->runpath_ = name;
}

const std::string& DynamicEntryRunPath::runpath(void) const {
  return this->name();
}


void DynamicEntryRunPath::runpath(const std::string& runpath) {
  this->name(runpath);
}

void DynamicEntryRunPath::accept(Visitor& visitor) const {
  DynamicEntry::accept(visitor);
  visitor(*this); // Double dispatch to avoid down-casting
  visitor.visit(this->runpath());
}

std::ostream& DynamicEntryRunPath::print(std::ostream& os) const {
  DynamicEntry::print(os);
  os << std::hex
     << std::left
     << std::setw(10) << this->name();
  return os;
}
}
}


