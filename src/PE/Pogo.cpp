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
#include "LIEF/PE/Pogo.hpp"
#include "LIEF/PE/PogoEntry.hpp"

namespace LIEF {
namespace PE {

Pogo::Pogo(const Pogo&) = default;
Pogo& Pogo::operator=(const Pogo&) = default;
Pogo::~Pogo(void) = default;

Pogo::Pogo(void) :
  signature_{POGO_SIGNATURES::POGO_UNKNOWN}
{}


Pogo::Pogo(POGO_SIGNATURES signature, const std::vector<PogoEntry>& entries) :
  signature_{signature},
  entries_{entries}
{}

Pogo* Pogo::clone(void) const {
  return new Pogo{*this};
}


POGO_SIGNATURES Pogo::signature() const {
  return signature_;
}

it_pogo_entries Pogo::entries(void) {
  return this->entries_;
}

it_const_pogo_entries Pogo::entries(void) const {
  return this->entries_;
}

void Pogo::signature(POGO_SIGNATURES signature) {
  signature_ = signature;
}

void Pogo::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool Pogo::operator==(const Pogo& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Pogo::operator!=(const Pogo& rhs) const {
  return not (*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const Pogo& pogo_entry) {
  static constexpr size_t WIDTH = 22;

  os << std::hex;
  os << std::left;
  os << std::setfill(' ');

  os << std::setw(WIDTH) << "POGO Signature:"  << to_string(pogo_entry.signature()) << std::endl;
  for (const PogoEntry& entry : pogo_entry.entries()) {
    os << "  " << entry << std::endl;
  }
  return os;
}

} // namespace PE
} // namespace LIEF
