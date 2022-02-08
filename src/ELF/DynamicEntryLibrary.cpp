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
#include "LIEF/ELF/DynamicEntryLibrary.hpp"

#include <iomanip>
#include <utility>

namespace LIEF {
namespace ELF {

DynamicEntryLibrary& DynamicEntryLibrary::operator=(const DynamicEntryLibrary&) = default;
DynamicEntryLibrary::DynamicEntryLibrary(const DynamicEntryLibrary&) = default;

DynamicEntryLibrary::DynamicEntryLibrary() :
  DynamicEntry::DynamicEntry{DYNAMIC_TAGS::DT_NEEDED, 0}
{}

DynamicEntryLibrary::DynamicEntryLibrary(std::string name) :
  DynamicEntry::DynamicEntry{DYNAMIC_TAGS::DT_NEEDED, 0},
  libname_{std::move(name)}
{}

const std::string& DynamicEntryLibrary::name() const {
  return libname_;
}


void DynamicEntryLibrary::name(const std::string& name) {
  libname_ = name;
}


void DynamicEntryLibrary::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool DynamicEntryLibrary::classof(const DynamicEntry* entry) {
  const DYNAMIC_TAGS tag = entry->tag();
  return tag == DYNAMIC_TAGS::DT_NEEDED;
}

std::ostream& DynamicEntryLibrary::print(std::ostream& os) const {

  DynamicEntry::print(os);
  os << std::hex
     << std::left
     << std::setw(10) << name();
  return os;

}
}
}



