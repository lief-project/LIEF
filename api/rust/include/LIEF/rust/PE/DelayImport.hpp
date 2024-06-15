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

#include "LIEF/PE/DelayImport.hpp"
#include "LIEF/rust/PE/DelayImportEntry.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/Iterator.hpp"

#include <memory>

class PE_DelayImport : private Mirror<LIEF::PE::DelayImport> {
  public:
  using lief_t = LIEF::PE::DelayImport;
  using Mirror::Mirror;

  class it_entries :
      public Iterator<PE_DelayImportEntry, LIEF::PE::DelayImport::it_const_entries>
  {
    public:
    it_entries(const PE_DelayImport::lief_t& src)
      : Iterator(std::move(src.entries())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  uint32_t attribute() const { return get().attribute(); }
  std::string name() const { return get().name(); }
  uint32_t handle() const { return get().handle(); }
  uint32_t iat() const { return get().iat(); }
  uint32_t names_table() const { return get().names_table(); }
  uint32_t biat() const { return get().biat(); }
  uint32_t uiat() const { return get().uiat(); }
  uint32_t timestamp() const { return get().timestamp(); }

  auto entries() const {
    return std::make_unique<it_entries>(get());
  }
};
