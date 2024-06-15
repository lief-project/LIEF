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

#include "LIEF/PE/Export.hpp"
#include "LIEF/rust/PE/ExportEntry.hpp"
#include "LIEF/rust/Iterator.hpp"

#include <memory>

class PE_Export : private Mirror<LIEF::PE::Export>{
  public:
  using lief_t = LIEF::PE::Export;
  using Mirror::Mirror;

  class it_entries :
      public Iterator<PE_ExportEntry, LIEF::PE::Export::it_const_entries>
  {
    public:
    it_entries(const PE_Export::lief_t& src)
      : Iterator(std::move(src.entries())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  uint32_t export_flags() const { return get().export_flags(); }
  uint32_t timestamp() const { return get().timestamp(); }
  uint32_t major_version() const { return get().major_version(); }
  uint32_t minor_version() const { return get().minor_version(); }
  uint32_t ordinal_base() const { return get().ordinal_base(); }
  std::string name() const { return get().name(); }

  auto entries() const {
    return std::make_unique<it_entries>(get());
  }
};
