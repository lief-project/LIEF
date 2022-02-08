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

#include "LIEF/PE/RichEntry.hpp"

namespace LIEF {
namespace PE {

RichEntry::~RichEntry() = default;
RichEntry::RichEntry(const RichEntry&) = default;
RichEntry& RichEntry::operator=(const RichEntry&) = default;

RichEntry::RichEntry() :
  id_{0},
  build_id_{0},
  count_{0}
{}

RichEntry::RichEntry(uint16_t id, uint16_t build_id, uint32_t count) :
  id_{id},
  build_id_{build_id},
  count_{count}
{}


uint16_t RichEntry::id() const {
  return id_;
}

uint16_t RichEntry::build_id() const {
  return build_id_;
}

uint32_t RichEntry::count() const {
  return count_;
}

void RichEntry::id(uint16_t id) {
  id_ = id;
}

void RichEntry::build_id(uint16_t build_id) {
  build_id_ = build_id;
}

void RichEntry::count(uint32_t count) {
  count_ = count;
}

void RichEntry::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool RichEntry::operator==(const RichEntry& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool RichEntry::operator!=(const RichEntry& rhs) const {
  return !(*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const RichEntry& rich_entry) {
  os << "ID: 0x"       << std::hex << std::setw(4) << std::setfill('0') << rich_entry.id() << " ";
  os << "Build ID: 0x" << std::hex << std::setw(4) << std::setfill('0') << rich_entry.build_id() << " ";
  os << "Count: "      << std::dec << std::setw(0) << rich_entry.count();
  return os;
}

}
}
