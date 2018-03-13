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
#include <iomanip>

#include "LIEF/PE/hash.hpp"

#include "LIEF/PE/RichHeader.hpp"

namespace LIEF {
namespace PE {

RichHeader::~RichHeader(void) = default;
RichHeader::RichHeader(const RichHeader&) = default;
RichHeader& RichHeader::operator=(const RichHeader&) = default;

RichHeader::RichHeader(void) :
  key_{0},
  entries_{}
{}

uint32_t RichHeader::key(void) const {
  return this->key_;
}

it_rich_entries RichHeader::entries(void) {
  return {this->entries_};
}

it_const_rich_entries RichHeader::entries(void) const {
  return {this->entries_};
}

void RichHeader::key(uint32_t key) {
  this->key_ = key;
}

void RichHeader::add_entry(const RichEntry& entry) {
  this->entries_.push_back(entry);
}

void RichHeader::add_entry(uint16_t id, uint16_t build_id, uint32_t count) {
  this->entries_.emplace_back(id, build_id, count);
}

void RichHeader::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool RichHeader::operator==(const RichHeader& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool RichHeader::operator!=(const RichHeader& rhs) const {
  return not (*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const RichHeader& rich_header) {
  os << "Key: " << std::hex << rich_header.key() << std::endl;
  for (const RichEntry& entry : rich_header.entries()) {
    os << "  - " << entry << std::endl;
  }
  return os;
}

}
}
