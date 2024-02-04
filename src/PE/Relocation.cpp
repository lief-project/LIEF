/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include "LIEF/Visitor.hpp"

#include "PE/Structures.hpp"
#include "LIEF/PE/Relocation.hpp"
#include "LIEF/PE/RelocationEntry.hpp"

#include <spdlog/fmt/fmt.h>

namespace LIEF {
namespace PE {

Relocation::Relocation(const Relocation& other) :
  Object{other},
  block_size_{other.block_size_},
  virtual_address_{other.virtual_address_}
{
  entries_.reserve(other.entries_.size());
  for (const std::unique_ptr<RelocationEntry>& r : other.entries_) {
    auto copy = std::make_unique<RelocationEntry>(*r);
    copy->relocation_ = this;
    entries_.push_back(std::move(copy));
  }
}

Relocation& Relocation::operator=(Relocation other) {
  swap(other);
  return *this;
}

Relocation::Relocation(const details::pe_base_relocation_block& header) :
  block_size_{header.BlockSize},
  virtual_address_{header.PageRVA}
{}


void Relocation::swap(Relocation& other) {
  std::swap(block_size_,      other.block_size_);
  std::swap(virtual_address_, other.virtual_address_);
  std::swap(entries_,         other.entries_);
}

RelocationEntry& Relocation::add_entry(const RelocationEntry& entry) {
  auto newone = std::make_unique<RelocationEntry>(entry);
  newone->relocation_ = this;
  entries_.push_back(std::move(newone));
  return *entries_.back();
}

void Relocation::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const Relocation& relocation) {
  os << fmt::format("0x{:06x} 0x{:06x}\n", relocation.virtual_address(),
                    relocation.block_size());

  for (const RelocationEntry& entry : relocation.entries()) {
    os << "    - " << entry << '\n';
  }

  return os;
}

}
}
