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

#include "LIEF/PE/hash.hpp"

#include "LIEF/PE/Structures.hpp"
#include "LIEF/PE/Relocation.hpp"
#include "LIEF/PE/RelocationEntry.hpp"

namespace LIEF {
namespace PE {

Relocation::Relocation(const Relocation& other) :
  Object{other},
  block_size_{other.block_size_},
  virtual_address_{other.virtual_address_}
{
  entries_.reserve(other.entries_.size());
  for (RelocationEntry* r : other.entries_) {
    auto* copy = new RelocationEntry{*r};
    copy->relocation_ = this;
    entries_.push_back(copy);
  }

}

Relocation& Relocation::operator=(Relocation other) {
  swap(other);
  return *this;
}


Relocation::~Relocation() {
  for (RelocationEntry* entry : entries_) {
    delete entry;
  }
}


Relocation::Relocation() :
  block_size_{0},
  virtual_address_{0}
{}


Relocation::Relocation(const details::pe_base_relocation_block& header) :
  block_size_{header.BlockSize},
  virtual_address_{header.PageRVA}
{}


void Relocation::swap(Relocation& other) {
  std::swap(block_size_,      other.block_size_);
  std::swap(virtual_address_, other.virtual_address_);
  std::swap(entries_,         other.entries_);
}


uint32_t Relocation::virtual_address() const {
  return virtual_address_;
}


uint32_t Relocation::block_size() const {
  return block_size_;
}

it_const_relocation_entries Relocation::entries() const {
  return entries_;
}


it_relocation_entries Relocation::entries() {
  return entries_;
}



RelocationEntry& Relocation::add_entry(const RelocationEntry& entry) {
  auto* newone = new RelocationEntry{entry};
  newone->relocation_ = this;
  entries_.push_back(newone);
  return *newone;
}


void Relocation::virtual_address(uint32_t virtual_address) {
  virtual_address_ = virtual_address;
}


void Relocation::block_size(uint32_t block_size) {
  block_size_ = block_size;
}


void Relocation::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool Relocation::operator==(const Relocation& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Relocation::operator!=(const Relocation& rhs) const {
  return !(*this == rhs);
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
