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
#include <string>
#include <LIEF/ELF/Binary.hpp>
#include <LIEF/ELF/Parser.hpp>

#include "LIEF/rust/Iterator.hpp"
#include "LIEF/rust/Abstract/Binary.hpp"
#include "LIEF/rust/ELF/GnuHash.hpp"
#include "LIEF/rust/ELF/Sysvhash.hpp"
#include "LIEF/rust/ELF/SymbolVersion.hpp"
#include "LIEF/rust/ELF/SymbolVersionDefinition.hpp"
#include "LIEF/rust/ELF/SymbolVersionRequirement.hpp"
#include "LIEF/rust/ELF/Segment.hpp"
#include "LIEF/rust/ELF/Section.hpp"
#include "LIEF/rust/ELF/Symbol.hpp"
#include "LIEF/rust/ELF/Relocation.hpp"
#include "LIEF/rust/ELF/Header.hpp"
#include "LIEF/rust/ELF/Note.hpp"
#include "LIEF/rust/ELF/DynamicEntry.hpp"

class ELF_Binary : public AbstractBinary {
  public:
  using lief_t = LIEF::ELF::Binary;
  ELF_Binary(std::unique_ptr<lief_t> bin) : AbstractBinary(std::move(bin)) {}

  static auto parse(std::string path) {
    return details::try_unique<ELF_Binary>(LIEF::ELF::Parser::parse(path));
  }

  class it_sections :
      public Iterator<ELF_Section, LIEF::ELF::Binary::it_const_sections>
  {
    public:
    it_sections(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.sections())) { }
    auto next() { return Iterator::next(); }
  };

  class it_segments :
      public Iterator<ELF_Segment, LIEF::ELF::Binary::it_const_segments>
  {
    public:
    it_segments(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.segments())) { }
    auto next() { return Iterator::next(); }
  };

  class it_dynamic_entries :
      public Iterator<ELF_DynamicEntry, LIEF::ELF::Binary::it_const_dynamic_entries>
  {
    public:
    it_dynamic_entries(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.dynamic_entries())) { }
    auto next() { return Iterator::next(); }
  };

  class it_dynamic_symbols :
      public Iterator<ELF_Symbol, LIEF::ELF::Binary::it_const_dynamic_symbols>
  {
    public:
    it_dynamic_symbols(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.dynamic_symbols())) { }
    auto next() { return Iterator::next(); }
  };

  class it_exported_symbols :
      public Iterator<ELF_Symbol, LIEF::ELF::Binary::it_const_exported_symbols>
  {
    public:
    it_exported_symbols(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.exported_symbols())) { }
    auto next() { return Iterator::next(); }
  };

  class it_imported_symbols :
      public Iterator<ELF_Symbol, LIEF::ELF::Binary::it_const_imported_symbols>
  {
    public:
    it_imported_symbols(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.imported_symbols())) { }
    auto next() { return Iterator::next(); }
  };

  class it_notes :
      public Iterator<ELF_Note, LIEF::ELF::Binary::it_const_notes>
  {
    public:
    it_notes(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.notes())) { }
    auto next() { return Iterator::next(); }
  };

  class it_symtab_symbols :
      public Iterator<ELF_Symbol, LIEF::ELF::Binary::it_const_symtab_symbols>
  {
    public:
    it_symtab_symbols(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.symtab_symbols())) { }
    auto next() { return Iterator::next(); }
  };

  class it_relocations :
      public Iterator<ELF_Relocation, LIEF::ELF::Binary::it_const_relocations>
  {
    public:
    it_relocations(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.relocations())) { }
    auto next() { return Iterator::next(); }
  };

  class it_pltgot_relocations :
      public Iterator<ELF_Relocation, LIEF::ELF::Binary::it_const_pltgot_relocations>
  {
    public:
    it_pltgot_relocations(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.pltgot_relocations())) { }
    auto next() { return Iterator::next(); }
  };

  class it_dynamic_relocations :
      public Iterator<ELF_Relocation, LIEF::ELF::Binary::it_const_dynamic_relocations>
  {
    public:
    it_dynamic_relocations(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.dynamic_relocations())) { }
    auto next() { return Iterator::next(); }
  };

  class it_object_relocations :
      public Iterator<ELF_Relocation, LIEF::ELF::Binary::it_const_object_relocations>
  {
    public:
    it_object_relocations(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.object_relocations())) { }
    auto next() { return Iterator::next(); }
  };

  class it_symbols_version :
      public Iterator<ELF_SymbolVersion, LIEF::ELF::Binary::it_const_symbols_version>
  {
    public:
    it_symbols_version(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.symbols_version())) { }
    auto next() { return Iterator::next(); }
  };

  class it_symbols_version_requirement :
      public Iterator<ELF_SymbolVersionRequirement, LIEF::ELF::Binary::it_const_symbols_version_requirement>
  {
    public:
    it_symbols_version_requirement(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.symbols_version_requirement())) { }
    auto next() { return Iterator::next(); }
  };

  class it_symbols_version_definition :
      public Iterator<ELF_SymbolVersionDefinition, LIEF::ELF::Binary::it_const_symbols_version_definition>
  {
    public:
    it_symbols_version_definition(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.symbols_version_definition())) { }
    auto next() { return Iterator::next(); }
  };

  auto header() const {
    return std::make_unique<ELF_Header>(impl().header());
  }

  auto gnu_hash() const {
    return details::try_unique<ELF_GnuHash>(impl().gnu_hash());
  }

  auto sysv_hash() const {
    return details::try_unique<ELF_SysvHash>(impl().sysv_hash());
  }

  auto sections() const {
    return std::make_unique<it_sections>(impl());
  }

  auto segments() const {
    return std::make_unique<it_segments>(impl());
  }

  auto dynamic_entries() const {
    return std::make_unique<it_dynamic_entries>(impl());
  }

  auto dynamic_symbols() const {
    return std::make_unique<it_dynamic_symbols>(impl());
  }

  auto exported_symbols() const {
    return std::make_unique<it_exported_symbols>(impl());
  }

  auto imported_symbols() const {
    return std::make_unique<it_imported_symbols>(impl());
  }

  auto symtab_symbols() const {
    return std::make_unique<it_symtab_symbols>(impl());
  }

  auto notes() const {
    return std::make_unique<it_notes>(impl());
  }

  auto relocations() const {
    return std::make_unique<it_relocations>(impl());
  }

  auto pltgot_relocations() const {
    return std::make_unique<it_pltgot_relocations>(impl());
  }

  auto dynamic_relocations() const {
    return std::make_unique<it_dynamic_relocations>(impl());
  }

  auto object_relocations() const {
    return std::make_unique<it_object_relocations>(impl());
  }

  auto symbols_version() const {
    return std::make_unique<it_symbols_version>(impl());
  }

  auto symbols_version_requirement() const {
    return std::make_unique<it_symbols_version_requirement>(impl());
  }

  auto symbols_version_definition() const {
    return std::make_unique<it_symbols_version_definition>(impl());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
