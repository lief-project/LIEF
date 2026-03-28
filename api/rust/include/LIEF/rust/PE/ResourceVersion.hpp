/* Copyright 2024 - 2026 R. Thomas
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
#include <string>
#include <vector>

#include "LIEF/PE/resources/ResourceVersion.hpp"
#include "LIEF/PE/resources/ResourceStringFileInfo.hpp"
#include "LIEF/PE/resources/ResourceVarFileInfo.hpp"
#include "LIEF/PE/resources/ResourceStringTable.hpp"
#include "LIEF/PE/resources/ResourceVar.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/Iterator.hpp"

class PE_ResourceStringTable_entry_t : private Mirror<LIEF::PE::ResourceStringTable::entry_t> {
  public:
  using lief_t = LIEF::PE::ResourceStringTable::entry_t;
  using Mirror::Mirror;

  auto key() const { return get().key_u8(); }
  auto value() const { return get().value_u8(); }
};

class PE_ResourceStringTable : private Mirror<LIEF::PE::ResourceStringTable> {
  public:
  using lief_t = LIEF::PE::ResourceStringTable;
  using Mirror::Mirror;

  class it_entries :
      public Iterator<PE_ResourceStringTable_entry_t,
                               LIEF::PE::ResourceStringTable::it_const_entries>
  {
    public:
    it_entries(const PE_ResourceStringTable::lief_t& src)
      : Iterator(src.entries()) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  auto get_type() const { return get().type(); }
  auto key() const { return get().key_u8(); }
  auto entries() const { return std::make_unique<it_entries>(get()); }
};

class PE_ResourceVar : private Mirror<LIEF::PE::ResourceVar> {
  public:
  using lief_t = LIEF::PE::ResourceVar;
  using Mirror::Mirror;

  auto get_type() const { return get().type(); }
  auto key() const { return get().key_u8(); }

  auto values() const {
    const auto& v = get().values();
    return std::vector<uint64_t>(v.begin(), v.end());
  }
};

class PE_ResourceStringFileInfo : private Mirror<LIEF::PE::ResourceStringFileInfo> {
  public:
  using lief_t = LIEF::PE::ResourceStringFileInfo;
  using Mirror::Mirror;

  class it_children :
      public Iterator<PE_ResourceStringTable, lief_t::it_const_elements>
  {
    public:
    it_children(const PE_ResourceStringFileInfo::lief_t& src)
      : Iterator(src.children()) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  auto get_type() const { return get().type(); }
  auto key() const { return get().key_u8(); }
  auto children() const { return std::make_unique<it_children>(get()); }
};

class PE_ResourceVarFileInfo : private Mirror<LIEF::PE::ResourceVarFileInfo> {
  public:
  using lief_t = LIEF::PE::ResourceVarFileInfo;
  using Mirror::Mirror;

  class it_vars :
      public Iterator<PE_ResourceVar, lief_t::it_const_vars>
  {
    public:
    it_vars(const PE_ResourceVarFileInfo::lief_t& src)
      : Iterator(src.vars()) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  auto get_type() const { return get().type(); }
  auto key() const { return get().key_u8(); }
  auto vars() const { return std::make_unique<it_vars>(get()); }
};

class PE_ResourceVersion : private Mirror<LIEF::PE::ResourceVersion> {
  public:
  using lief_t = LIEF::PE::ResourceVersion;
  using Mirror::Mirror;

  auto get_type() const { return get().type(); }
  auto key() const { return get().key_u8(); }

  auto file_info_signature() const { return get().file_info().signature; }
  auto file_info_struct_version() const { return get().file_info().struct_version; }
  auto file_info_file_version_ms() const { return get().file_info().file_version_ms; }
  auto file_info_file_version_ls() const { return get().file_info().file_version_ls; }
  auto file_info_product_version_ms() const { return get().file_info().product_version_ms; }
  auto file_info_product_version_ls() const { return get().file_info().product_version_ls; }
  auto file_info_file_flags_mask() const { return get().file_info().file_flags_mask; }
  auto file_info_file_flags() const { return get().file_info().file_flags; }
  auto file_info_file_os() const { return get().file_info().file_os; }
  auto file_info_file_type() const { return get().file_info().file_type; }
  auto file_info_file_subtype() const { return get().file_info().file_subtype; }
  auto file_info_file_date_ms() const { return get().file_info().file_date_ms; }
  auto file_info_file_date_ls() const { return get().file_info().file_date_ls; }

  auto string_file_info() const {
    return details::try_unique<PE_ResourceStringFileInfo>(get().string_file_info());
  }

  auto var_file_info() const {
    return details::try_unique<PE_ResourceVarFileInfo>(get().var_file_info());
  }
};
