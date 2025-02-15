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
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/Iterator.hpp"
#include "LIEF/PE/LoadConfigurations/VolatileMetadata.hpp"

class PE_VolatileMetadata_range_t : public Mirror<LIEF::PE::VolatileMetadata::range_t> {
  public:
  using lief_t = LIEF::PE::VolatileMetadata::range_t;
  using Mirror::Mirror;

  auto start() const { return get().start; }
  auto size() const { return get().size; }
  auto end() const { return get().end(); }
};

class PE_VolatileMetadata : public Mirror<LIEF::PE::VolatileMetadata> {
  public:
  using lief_t = LIEF::PE::VolatileMetadata;
  using Mirror::Mirror;

  class it_ranges :
      public Iterator<PE_VolatileMetadata_range_t, LIEF::PE::VolatileMetadata::it_const_info_ranges_t>
  {
    public:
    it_ranges(const PE_VolatileMetadata::lief_t& src)
      : Iterator(std::move(src.info_ranges())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  auto size() const { return get().size(); }
  auto min_version() const { return get().min_version(); }
  auto max_version() const { return get().max_version(); }
  auto access_table_rva() const { return get().access_table_rva(); }
  auto access_table_size() const { return get().access_table_size(); }
  auto info_range_rva() const { return get().info_range_rva(); }
  auto info_ranges_size() const { return get().info_ranges_size(); }

  const auto& access_table() const { return get().access_table(); }

  auto info_ranges() const  {
    return std::make_unique<it_ranges>(get());
  }


  std::string to_string() const { return get().to_string(); }
};


