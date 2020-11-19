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
#include <sstream>
#include <numeric>

#include "LIEF/PE/hash.hpp"

#include "LIEF/PE/EnumToString.hpp"
#include "LIEF/PE/PogoEntry.hpp"

namespace LIEF {
namespace PE {

PogoEntry::PogoEntry(const PogoEntry&) = default;
PogoEntry& PogoEntry::operator=(const PogoEntry&) = default;
PogoEntry::~PogoEntry(void) = default;

PogoEntry::PogoEntry(void) :
  start_rva_{0}, size_{0}, name_{}
{}

PogoEntry::PogoEntry(uint32_t start_rva, uint32_t size, const std::string& name) :
  start_rva_{start_rva}, size_{size}, name_{name}
{}


void PogoEntry::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool PogoEntry::operator==(const PogoEntry& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool PogoEntry::operator!=(const PogoEntry& rhs) const {
  return not (*this == rhs);
}

uint32_t PogoEntry::start_rva() const {
  return this->start_rva_;
}

uint32_t PogoEntry::size() const {
  return this->size_;
}

const std::string& PogoEntry::name() const {
  return this->name_;
}

void PogoEntry::start_rva(uint32_t start_rva){
  this->start_rva_ = start_rva;
}

void PogoEntry::size(uint32_t size){
  this->size_ = size;
}

void PogoEntry::name(const std::string& name){
  this->name_ = name;
}


std::ostream& operator<<(std::ostream& os, const PogoEntry& entry) {
  os << std::hex;
  os << std::left;
  os << std::setfill(' ');

  os << std::setw(23) << entry.name() << " ";
  os << std::setw(10) << entry.start_rva();
  os << "(" << entry.size() << ")";

  return os;
}

} // namespace PE
} // namespace LIEF
