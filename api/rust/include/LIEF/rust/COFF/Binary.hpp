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

#include "LIEF/COFF/Binary.hpp"
#include "LIEF/COFF/Parser.hpp"
#include "LIEF/rust/COFF/Relocation.hpp"
#include "LIEF/rust/COFF/Symbol.hpp"
#include "LIEF/rust/COFF/String.hpp"
#include "LIEF/rust/COFF/Section.hpp"
#include "LIEF/rust/COFF/Header.hpp"
#include "LIEF/rust/Mirror.hpp"

class COFF_Binary : Mirror<LIEF::COFF::Binary> {
  public:
  using lief_t = LIEF::COFF::Binary;
  using Mirror::Mirror;

  class it_relocations :
      public Iterator<COFF_Relocation, LIEF::COFF::Binary::it_const_relocations>
  {
    public:
    it_relocations(const COFF_Binary::lief_t& src)
      : Iterator(std::move(src.relocations())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_symbols :
      public Iterator<COFF_Symbol, LIEF::COFF::Binary::it_const_symbols>
  {
    public:
    it_symbols(const COFF_Binary::lief_t& src)
      : Iterator(std::move(src.symbols())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_sections :
      public Iterator<COFF_Section, LIEF::COFF::Binary::it_const_sections>
  {
    public:
    it_sections(const COFF_Binary::lief_t& src)
      : Iterator(std::move(src.sections())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_strings :
      public Iterator<COFF_String, LIEF::COFF::Binary::it_const_strings_table>
  {
    public:
    it_strings(const COFF_Binary::lief_t& src)
      : Iterator(std::move(src.string_table())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  static auto parse(std::string path) { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<COFF_Binary>(LIEF::COFF::Parser::parse(path));
  }

  auto header() const {
    return std::make_unique<COFF_Header>(get().header());
  }

  auto sections() const {
    return std::make_unique<it_sections>(get());
  }

  auto symbols() const {
    return std::make_unique<it_symbols>(get());
  }

  auto relocations() const {
    return std::make_unique<it_relocations>(get());
  }

  auto string_table() const {
    return std::make_unique<it_strings>(get());
  }

  auto find_string(uint32_t offset) const {
    return details::try_unique<COFF_String>(get().find_string(offset));
  }

  auto to_string() const {
    return get().to_string();
  }
};

