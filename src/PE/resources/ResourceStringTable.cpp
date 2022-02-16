/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
 * Copyright 2017 - 2021 K. Nakagawa
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

#include <utility>

#include "LIEF/utils.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/EnumToString.hpp"

#include "LIEF/PE/resources/ResourceStringTable.hpp"

namespace LIEF {
namespace PE {

ResourceStringTable::ResourceStringTable(const ResourceStringTable&) = default;
ResourceStringTable& ResourceStringTable::operator=(const ResourceStringTable&) = default;
ResourceStringTable::~ResourceStringTable() = default;

ResourceStringTable::ResourceStringTable() :
  length_{0}
{}

ResourceStringTable::ResourceStringTable(int16_t length, std::u16string name) :
  name_{std::move(name)},
  length_{length}
{}

int16_t ResourceStringTable::length() const {
  return length_;
}

const std::u16string& ResourceStringTable::name() const {
  return name_;
}

void ResourceStringTable::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool ResourceStringTable::operator==(const ResourceStringTable& rhs) const {
  if (this == &rhs) {
    return true;
  }
  return Hash::hash(*this) == Hash::hash(rhs);
}

bool ResourceStringTable::operator!=(const ResourceStringTable& rhs) const {
  return !(*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const ResourceStringTable& string_table) {
  os << u16tou8(string_table.name()) << "\n";
  return os;
}

}
}
