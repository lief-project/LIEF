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
#include "LIEF/rust/ELF/DynamicEntryLibrary.hpp"
#include "LIEF/rust/ELF/Segment.hpp"
#include "LIEF/rust/ELF/Section.hpp"
#include "LIEF/rust/ELF/Symbol.hpp"
#include "LIEF/rust/ELF/Relocation.hpp"
#include "LIEF/rust/ELF/Header.hpp"
#include "LIEF/rust/ELF/Note.hpp"
#include "LIEF/rust/ELF/DynamicEntry.hpp"

#include "LIEF/rust/error.hpp"

class ELF_Binary : public AbstractBinary {
  public:
  using lief_t = LIEF::ELF::Binary;
  ELF_Binary(std::unique_ptr<lief_t> bin) : AbstractBinary(std::move(bin)) {}

  static auto parse(std::string path) { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<ELF_Binary>(LIEF::ELF::Parser::parse(path));
  }

  class it_sections :
      public Iterator<ELF_Section, LIEF::ELF::Binary::it_const_sections>
  {
    public:
    it_sections(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.sections())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_segments :
      public Iterator<ELF_Segment, LIEF::ELF::Binary::it_const_segments>
  {
    public:
    it_segments(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.segments())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_dynamic_entries :
      public Iterator<ELF_DynamicEntry, LIEF::ELF::Binary::it_const_dynamic_entries>
  {
    public:
    it_dynamic_entries(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.dynamic_entries())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_dynamic_symbols :
      public Iterator<ELF_Symbol, LIEF::ELF::Binary::it_const_dynamic_symbols>
  {
    public:
    it_dynamic_symbols(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.dynamic_symbols())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_exported_symbols :
      public Iterator<ELF_Symbol, LIEF::ELF::Binary::it_const_exported_symbols>
  {
    public:
    it_exported_symbols(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.exported_symbols())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_imported_symbols :
      public Iterator<ELF_Symbol, LIEF::ELF::Binary::it_const_imported_symbols>
  {
    public:
    it_imported_symbols(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.imported_symbols())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_notes :
      public Iterator<ELF_Note, LIEF::ELF::Binary::it_const_notes>
  {
    public:
    it_notes(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.notes())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_symtab_symbols :
      public Iterator<ELF_Symbol, LIEF::ELF::Binary::it_const_symtab_symbols>
  {
    public:
    it_symtab_symbols(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.symtab_symbols())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_relocations :
      public Iterator<ELF_Relocation, LIEF::ELF::Binary::it_const_relocations>
  {
    public:
    it_relocations(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.relocations())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_pltgot_relocations :
      public Iterator<ELF_Relocation, LIEF::ELF::Binary::it_const_pltgot_relocations>
  {
    public:
    it_pltgot_relocations(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.pltgot_relocations())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_dynamic_relocations :
      public Iterator<ELF_Relocation, LIEF::ELF::Binary::it_const_dynamic_relocations>
  {
    public:
    it_dynamic_relocations(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.dynamic_relocations())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_object_relocations :
      public Iterator<ELF_Relocation, LIEF::ELF::Binary::it_const_object_relocations>
  {
    public:
    it_object_relocations(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.object_relocations())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_symbols_version :
      public Iterator<ELF_SymbolVersion, LIEF::ELF::Binary::it_const_symbols_version>
  {
    public:
    it_symbols_version(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.symbols_version())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_symbols_version_requirement :
      public Iterator<ELF_SymbolVersionRequirement, LIEF::ELF::Binary::it_const_symbols_version_requirement>
  {
    public:
    it_symbols_version_requirement(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.symbols_version_requirement())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_symbols_version_definition :
      public Iterator<ELF_SymbolVersionDefinition, LIEF::ELF::Binary::it_const_symbols_version_definition>
  {
    public:
    it_symbols_version_definition(const ELF_Binary::lief_t& src)
      : Iterator(std::move(src.symbols_version_definition())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  auto header() const {
    return std::make_unique<ELF_Header>(impl().header());
  }

  auto gnu_hash() const {
    return details::try_unique<ELF_GnuHash>(impl().gnu_hash()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto sysv_hash() const {
    return details::try_unique<ELF_SysvHash>(impl().sysv_hash()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
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

  auto section_by_name(std::string name) const { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<ELF_Section>(impl().get_section(name)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto relocation_by_addr(uint64_t addr) const {
    return details::try_unique<ELF_Relocation>(impl().get_relocation(addr)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto relocation_for_symbol(std::string name) const { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<ELF_Relocation>(impl().get_relocation(name)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto get_dynamic_symbol(std::string name) const { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<ELF_Symbol>(impl().get_dynamic_symbol(name)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto get_symtab_symbol(std::string name) const { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<ELF_Symbol>(impl().get_symtab_symbol(name)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto get_library(std::string name) const { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<ELF_DynamicEntryLibrary>(impl().get_library(name)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto section_from_offset(uint64_t offset, bool skip_nobits) const {
    return details::try_unique<ELF_Section>(impl().section_from_offset(offset, skip_nobits)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto section_from_virtual_address(uint64_t address, bool skip_nobits) const {
    return details::try_unique<ELF_Section>(impl().section_from_virtual_address(address, skip_nobits)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto segment_from_virtual_address(uint64_t address) const {
    return details::try_unique<ELF_Segment>(impl().segment_from_virtual_address(address)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto segment_from_offset(uint64_t offset) const {
    return details::try_unique<ELF_Segment>(impl().segment_from_offset(offset)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  Span get_content_from_virtual_address(uint64_t virtual_address, uint64_t size) const {
    return make_span(impl().get_content_from_virtual_address(virtual_address, size));
  }

  uint64_t virtual_address_to_offset(uint64_t virtual_address, uint32_t& error) const {
    return details::make_error<uint64_t>(
      impl().virtual_address_to_offset(virtual_address), error
    );
  }

  uint64_t virtual_size() const {
    return impl().virtual_size();
  }

  std::string interpreter() const {
    return impl().interpreter();
  }

  auto get_relocated_dynamic_array(uint64_t tag) const {
    return impl().get_relocated_dynamic_array(LIEF::ELF::DynamicEntry::TAG(tag));
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
