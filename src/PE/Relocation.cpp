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

#include "LIEF/visitors/Hash.hpp"

#include "LIEF/PE/Relocation.hpp"

namespace LIEF {
namespace PE {

Relocation::Relocation(const Relocation&)            = default;
Relocation& Relocation::operator=(const Relocation&) = default;
Relocation::~Relocation(void)                        = default;


Relocation::Relocation(void) :
  block_size_{0},
  virtual_address_{0},
  entries_{}
{}


Relocation::Relocation(const pe_base_relocation_block* header) :
  block_size_{header->BlockSize},
  virtual_address_{header->PageRVA},
  entries_{}
{}


uint32_t Relocation::virtual_address(void) const {
  return this->virtual_address_;
}


uint32_t Relocation::block_size(void) const {
  return this->block_size_;
}

const std::vector<RelocationEntry>& Relocation::entries(void) const {
  return this->entries_;
}


void Relocation::add_entry(const RelocationEntry& entry) {
  return this->entries_.push_back(entry);
}


void Relocation::virtual_address(uint32_t virtual_address) {
  this->virtual_address_ = virtual_address;
}


void Relocation::block_size(uint32_t block_size) {
  this->block_size_ = block_size;
}


void Relocation::accept(LIEF::Visitor& visitor) const {
  visitor.visit(this->virtual_address());
  for (const RelocationEntry& entry : this->entries_) {
    visitor(entry);
  }
}

bool Relocation::operator==(const Relocation& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Relocation::operator!=(const Relocation& rhs) const {
  return not (*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const Relocation& relocation) {

  os << std::hex << std::left;
  os << std::setw(10) << relocation.virtual_address();
  os << std::setw(10) << relocation.block_size();
  os << std::endl;
  for (const RelocationEntry& entry : relocation.entries()) {
    os << "    - " << entry << std::endl;
  }

  return os;
}

}
}
