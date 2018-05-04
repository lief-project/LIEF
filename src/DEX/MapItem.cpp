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
#include <numeric>

#include "LIEF/DEX/MapItem.hpp"
#include "LIEF/DEX/hash.hpp"
#include "LIEF/logging++.hpp"

#include "LIEF/DEX/EnumToString.hpp"

namespace LIEF {
namespace DEX {

MapItem::MapItem(void) = default;
MapItem::MapItem(const MapItem& other) = default;
MapItem& MapItem::operator=(const MapItem&) = default;

MapItem::MapItem(MapItem::TYPES type, uint32_t offset, uint32_t size, uint16_t reserved) :
  type_{type},
  reserved_{reserved},
  size_{size},
  offset_{offset}
{}

MapItem::TYPES MapItem::type(void) const {
  return this->type_;
}

uint16_t MapItem::reserved(void) const {
  return this->reserved_;
}

uint32_t MapItem::size(void) const {
  return this->size_;
}

uint32_t MapItem::offset(void) const {
  return this->offset_;
}

void MapItem::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool MapItem::operator==(const MapItem& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool MapItem::operator!=(const MapItem& rhs) const {
  return not (*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const MapItem& mitem) {
  os << to_string(mitem.type())
     << "@" << std::hex << std::showbase << mitem.offset()
     << " (" << mitem.size() << " bytes) - " << mitem.reserved();
  return os;
}


MapItem::~MapItem(void) = default;

}
}
