/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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

#include "LIEF/Abstract/hash.hpp"

#include "LIEF/Abstract/Relocation.hpp"

namespace LIEF {

Relocation::Relocation(void) = default;

Relocation::Relocation(uint64_t address, uint8_t size) :
  address_{address},
  size_{size}
{}


Relocation::~Relocation(void) = default;
Relocation& Relocation::operator=(const Relocation&) = default;
Relocation::Relocation(const Relocation&) = default;


void Relocation::swap(Relocation& other) {
  std::swap(this->address_, other.address_);
  std::swap(this->size_,    other.size_);
}

uint64_t Relocation::address(void) const {
  return this->address_;
}

size_t Relocation::size(void) const {
  return this->size_;
}


void Relocation::address(uint64_t address) {
  this->address_ = address;
}


void Relocation::size(size_t size) {
  this->size_ = static_cast<uint8_t>(size);
}

void Relocation::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool Relocation::operator==(const Relocation& rhs) const {
  size_t hash_lhs = AbstractHash::hash(*this);
  size_t hash_rhs = AbstractHash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Relocation::operator!=(const Relocation& rhs) const {
  return not (*this == rhs);
}


bool Relocation::operator<(const Relocation& rhs) const {
  return this->address() < rhs.address();
}

bool Relocation::operator<=(const Relocation& rhs) const {
  return not (this->address() > rhs.address());
}

bool Relocation::operator>(const Relocation& rhs) const {
  return this->address() > rhs.address();
}

bool Relocation::operator>=(const Relocation& rhs) const {
  return not (this->address() < rhs.address());
}

std::ostream& operator<<(std::ostream& os, const Relocation& entry) {
  os << std::hex;
  os << std::left
     << std::setw(10) << entry.address()
     << std::setw(4)  << std::dec << entry.size();
  return os;
}

}
