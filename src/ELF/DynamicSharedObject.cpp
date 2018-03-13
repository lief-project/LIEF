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
#include "LIEF/ELF/DynamicSharedObject.hpp"

#include <iomanip>

namespace LIEF {
namespace ELF {
DynamicSharedObject::DynamicSharedObject(void) :
  DynamicEntry::DynamicEntry{DYNAMIC_TAGS::DT_SONAME, 0},
  name_{}
{}

DynamicSharedObject& DynamicSharedObject::operator=(const DynamicSharedObject&) = default;

DynamicSharedObject::DynamicSharedObject(const DynamicSharedObject&) = default;

DynamicSharedObject::DynamicSharedObject(const std::string& name) :
  DynamicEntry::DynamicEntry{DYNAMIC_TAGS::DT_SONAME, 0},
  name_{name}
{}


const std::string& DynamicSharedObject::name(void) const {
  return this->name_;
}


void DynamicSharedObject::name(const std::string& name) {
  this->name_ = name;
}

void DynamicSharedObject::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


std::ostream& DynamicSharedObject::print(std::ostream& os) const {
  DynamicEntry::print(os);
  os << std::hex
     << std::left
     << std::setw(10) << this->name();
  return os;

}
}
}



