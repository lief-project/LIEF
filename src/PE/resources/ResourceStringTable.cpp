/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
 * Copyright 2020 K. Nakagawa
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

#include "LIEF/utils.hpp"

#include "LIEF/PE/utils.hpp"
#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/EnumToString.hpp"

#include "LIEF/PE/resources/ResourceStringTable.hpp"

namespace LIEF {
namespace PE {

ResourceStringTable::ResourceStringTable(const ResourceStringTable&) = default;
ResourceStringTable& ResourceStringTable::operator=(const ResourceStringTable&) = default;
ResourceStringTable::~ResourceStringTable(void) = default;

ResourceStringTable::ResourceStringTable(void) :
  name_{},
  length_{0}
{}

ResourceStringTable::ResourceStringTable(int16_t length, const std::u16string& name) :
  name_{name},
  length_{length}
{}

int16_t ResourceStringTable::length(void) const {
  return this->length_;
}

const std::u16string& ResourceStringTable::name(void) const {
  return this->name_;
}

void ResourceStringTable::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool ResourceStringTable::operator==(const ResourceStringTable& rhs) const {
  return Hash::hash(*this) == Hash::hash(rhs);
}

bool ResourceStringTable::operator!=(const ResourceStringTable& rhs) const {
  return not (*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const ResourceStringTable& string_table) {
  os << std::dec << "Length: " << string_table.length() << std::endl;
  os << "Name: \"" << u16tou8(string_table.name()) << "\"" << std::endl;
  return os;
}

}
}
