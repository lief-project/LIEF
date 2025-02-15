/* Copyright 2024 - 2025 R. Thomas
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

class PE_Export : public Mirror<LIEF::PE::Export>{
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

  static auto create() {
    return std::make_unique<PE_Export>(std::make_unique<lief_t>());
  }

  auto export_flags() const { return get().export_flags(); }
  auto timestamp() const { return get().timestamp(); }
  auto major_version() const { return get().major_version(); }
  auto minor_version() const { return get().minor_version(); }
  auto ordinal_base() const { return get().ordinal_base(); }

  auto name_rva() const { return get().name_rva(); }
  auto export_addr_table_rva() const { return get().export_addr_table_rva(); }
  auto export_addr_table_cnt() const { return get().export_addr_table_cnt(); }
  auto names_addr_table_rva() const { return get().names_addr_table_rva(); }
  auto names_addr_table_cnt() const { return get().names_addr_table_cnt(); }
  auto ord_addr_table_rva() const { return get().ord_addr_table_rva(); }

  std::string name() const { return get().name(); }

  auto entries() const {
    return std::make_unique<it_entries>(get());
  }

  void set_export_flags(uint32_t flags) { get().export_flags(flags); }
  void set_timestamp(uint32_t ts) { get().timestamp(ts); }
  void set_major_version(uint32_t version) { get().major_version(version); }
  void set_minor_version(uint32_t version) { get().minor_version(version); }
  void set_name(std::string name) { get().name(std::move(name)); }

  auto entry_by_name(std::string name) const {
    return details::try_unique<PE_ExportEntry>(get().find_entry(name));
  }

  auto entry_by_ordinal(uint32_t ord) const {
    return details::try_unique<PE_ExportEntry>(get().find_entry(ord));
  }

  auto entry_at_rva(uint32_t rva) const {
    return details::try_unique<PE_ExportEntry>(get().find_entry_at(rva));
  }

  auto add_entry(const PE_ExportEntry& entry) {
    return std::make_unique<PE_ExportEntry>(get().add_entry(as<LIEF::PE::ExportEntry>(&entry)));
  }

  auto add_entry_by_name(std::string name, uint32_t rva) {
    return std::make_unique<PE_ExportEntry>(get().add_entry(name, rva));
  }

  auto remove_entry(std::unique_ptr<PE_ExportEntry> entry) {
    return get().remove_entry(static_cast<LIEF::PE::ExportEntry&>((*entry).get()));
  }

  auto remove_entry_at(uint32_t rva) {
    return get().remove_entry(rva);
  }

  auto remove_entry_by_name(std::string name) {
    return get().remove_entry(name);
  }
};
