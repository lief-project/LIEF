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

#include "LIEF/PE/Import.hpp"
#include "LIEF/rust/PE/ImportEntry.hpp"
#include "LIEF/rust/PE/DataDirectories.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/Iterator.hpp"

#include <memory>

class PE_Import : private Mirror<LIEF::PE::Import> {
  public:
  using lief_t = LIEF::PE::Import;
  using Mirror::Mirror;

  class it_entries :
      public Iterator<PE_ImportEntry, LIEF::PE::Import::it_const_entries>
  {
    public:
    it_entries(const PE_Import::lief_t& src)
      : Iterator(std::move(src.entries())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  uint32_t forwarder_chain() const { return get().forwarder_chain(); }
  uint32_t timedatestamp() const { return get().timedatestamp(); }
  uint32_t import_address_table_rva() const { return get().import_address_table_rva(); }
  uint32_t import_lookup_table_rva() const { return get().import_lookup_table_rva(); }
  std::string name() const { return get().name(); }

  auto directory() const {
    return details::try_unique<PE_DataDirectory>(get().directory()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto iat_directory() const {
    return details::try_unique<PE_DataDirectory>(get().iat_directory()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto entries() const {
    return std::make_unique<it_entries>(get());
  }

  auto entry_by_name(std::string name) const { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<PE_ImportEntry>(get().get_entry(name)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

};
