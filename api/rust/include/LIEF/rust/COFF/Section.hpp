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
#include "LIEF/COFF/Section.hpp"
#include "LIEF/rust/Abstract/Section.hpp"
#include "LIEF/rust/COFF/Relocation.hpp"
#include "LIEF/rust/COFF/String.hpp"

#include "LIEF/rust/Iterator.hpp"

class COFF_Section_ComdataInfo : Mirror<LIEF::COFF::Section::ComdatInfo> {
  public:
  using Mirror::Mirror;
  auto symbol() const {
    return details::try_unique<COFF_Symbol>(get().symbol);
  }

  auto kind() const {
    return to_int(get().kind);
  }
};

class COFF_Section : public AbstractSection {
  public:
  using lief_t = LIEF::COFF::Section;

  COFF_Section(const lief_t& sec) : AbstractSection(sec) {}

  class it_relocations :
      public Iterator<COFF_Relocation, LIEF::COFF::Section::it_const_relocations>
  {
    public:
    it_relocations(const COFF_Section::lief_t& src)
      : Iterator(std::move(src.relocations())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_symbols :
      public Iterator<COFF_Symbol, LIEF::COFF::Section::it_const_symbols>
  {
    public:
    it_symbols(const COFF_Section::lief_t& src)
      : Iterator(std::move(src.symbols())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  auto sizeof_raw_data() const { return impl().sizeof_raw_data(); }
  auto virtual_size() const { return impl().virtual_size(); }
  auto pointerto_raw_data() const { return impl().pointerto_raw_data(); }
  auto pointerto_relocation() const { return impl().pointerto_relocation(); }
  auto pointerto_line_numbers() const { return impl().pointerto_line_numbers(); }
  auto numberof_relocations() const { return impl().numberof_relocations(); }
  auto numberof_line_numbers() const { return impl().numberof_line_numbers(); }
  auto characteristics() const { return impl().characteristics(); }

  auto is_discardable() const { return impl().is_discardable(); }

  auto has_extended_relocations() const { return impl().has_extended_relocations(); }

  auto relocations() const {
    return std::make_unique<it_relocations>(impl());
  }

  auto symbols() const {
    return std::make_unique<it_symbols>(impl());
  }

  auto comdat_info() const {
    return details::try_unique<COFF_Section_ComdataInfo>(impl().comdat_info());
  }

  auto coff_string() const {
    return details::try_unique<COFF_String>(impl().coff_string());
  }

  auto to_string() const {
    return impl().to_string();
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
