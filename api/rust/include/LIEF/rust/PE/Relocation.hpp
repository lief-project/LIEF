/* Copyright 2024 R. Thomas
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
#pragma once
#include <cstdint>

#include "LIEF/PE/Relocation.hpp"
#include "LIEF/rust/PE/RelocationEntry.hpp"
#include "LIEF/rust/Iterator.hpp"

class PE_Relocation : Mirror<LIEF::PE::Relocation> {
  public:
  using lief_t = LIEF::PE::Relocation;
  using Mirror::Mirror;

  class it_entries :
      public Iterator<PE_RelocationEntry, LIEF::PE::Relocation::it_const_entries>
  {
    public:
    it_entries(const PE_Relocation::lief_t& src)
      : Iterator(std::move(src.entries())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  uint32_t virtual_address() const { return get().virtual_address(); }
  uint32_t block_size() const { return get().block_size(); }

  auto entries() const {
    return std::make_unique<it_entries>(get());
  }
};
