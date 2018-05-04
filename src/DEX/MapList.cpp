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

#include "LIEF/DEX/MapList.hpp"
#include "LIEF/DEX/hash.hpp"
#include "LIEF/logging++.hpp"

namespace LIEF {
namespace DEX {

MapList::MapList(void) = default;
MapList::MapList(const MapList& other) = default;

MapList& MapList::operator=(const MapList&) = default;

MapList::it_items_t MapList::items(void) {
  std::vector<MapItem*> items;
  items.reserve(this->items_.size());
  std::transform(
      std::begin(this->items_),
      std::end(this->items_),
      std::back_inserter(items),
      [] (MapList::items_t::value_type& p) -> MapItem* {
        return &(p.second);
      });
  return items;

}

MapList::it_const_items_t MapList::items(void) const {
  std::vector<MapItem*> items;
  items.reserve(this->items_.size());
  std::transform(
      std::begin(this->items_),
      std::end(this->items_),
      std::back_inserter(items),
      [] (const MapList::items_t::value_type& p) -> MapItem* {
        return const_cast<MapItem*>(&(p.second));
      });
  return items;

}


bool MapList::has(MapItem::TYPES type) const {
  return this->items_.count(type) > 0;
}

const MapItem& MapList::get(MapItem::TYPES type) const {
  auto&& it = this->items_.find(type);
  CHECK_NE(it, std::end(this->items_));
  return it->second;
}

MapItem& MapList::get(MapItem::TYPES type) {
  return const_cast<MapItem&>(static_cast<const MapList*>(this)->get(type));
}

const MapItem& MapList::operator[](MapItem::TYPES type) const {
  return this->get(type);
}

MapItem& MapList::operator[](MapItem::TYPES type) {
  return this->get(type);
}

void MapList::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool MapList::operator==(const MapList& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool MapList::operator!=(const MapList& rhs) const {
  return not (*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const MapList& mlist) {
  for (const MapItem& item : mlist.items()) {
    os << item << std::endl;
  }
  return os;
}


MapList::~MapList(void) = default;

}
}
