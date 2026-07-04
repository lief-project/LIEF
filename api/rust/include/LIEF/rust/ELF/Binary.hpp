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
#include "LIEF/rust/helpers.hpp"
#include "LIEF/rust/Span.hpp"

class ELF_Binary_write_config_t {
  public:
  bool dt_hash = true;
  bool dyn_str = true;
  bool dynamic_section = true;
  bool fini_array = true;
  bool gnu_hash = true;
  bool init_array = true;
  bool interpreter = true;
  bool jmprel = true;
  bool notes = true;
  bool preinit_array = true;
  bool relr = true;
  bool android_rela = true;
  bool rela = true;
  bool static_symtab = true;
  bool sym_verdef = true;
  bool sym_verneed = true;
  bool sym_versym = true;
  bool symtab = true;
  bool coredump_notes = true;
  bool force_relocate = false;
  bool keep_empty_version_requirement = false;
  bool skip_dynamic = false;
};

class ELF_ParserConfig {
  public:
  static auto create() {
    return std::make_unique<ELF_ParserConfig>();
  }

  const LIEF::ELF::ParserConfig& conf() const {
    return config_;
  }

  auto set_parse_relocations(bool value) {
    config_.parse_relocations = value;
  }

  auto set_parse_dyn_symbols(bool value) {
    config_.parse_dyn_symbols = value;
  }

  auto set_parse_symtab_symbols(bool value) {
    config_.parse_symtab_symbols = value;
  }

  auto set_parse_symbol_versions(bool value) {
    config_.parse_symbol_versions = value;
  }

  auto set_parse_notes(bool value) {
    config_.parse_notes = value;
  }

  auto set_parse_overlay(bool value) {
    config_.parse_overlay = value;
  }

  auto set_count_mtd(uint32_t value) {
    config_.count_mtd = (LIEF::ELF::ParserConfig::DYNSYM_COUNT)value;
  }

  auto set_page_size(uint64_t value) {
    config_.page_size = value;
  }

  private:
  LIEF::ELF::ParserConfig config_;
};


class ELF_Binary : public AbstractBinary {
  public:
  using lief_t = LIEF::ELF::Binary;
  ELF_Binary(std::unique_ptr<lief_t> bin) :
    AbstractBinary(std::move(bin)) {}

  static auto parse(const std::string& path) {
    return details::try_unique<ELF_Binary>(LIEF::ELF::Parser::parse(path));
  }

  static auto parse_with_config(const std::string& path,
                                const ELF_ParserConfig& config) {
    return details::try_unique<ELF_Binary>(
        LIEF::ELF::Parser::parse(path, config.conf())
    );
  }

  class it_sections
    : public Iterator<ELF_Section, LIEF::ELF::Binary::it_const_sections> {
    public:
    it_sections(const ELF_Binary::lief_t& src) :
      Iterator(src.sections()) {}
    auto next() {
      return Iterator::next();
    }
    auto size() const {
      return Iterator::size();
    }
  };

  class it_segments
    : public Iterator<ELF_Segment, LIEF::ELF::Binary::it_const_segments> {
    public:
    it_segments(const ELF_Binary::lief_t& src) :
      Iterator(src.segments()) {}
    auto next() {
      return Iterator::next();
    }
    auto size() const {
      return Iterator::size();
    }
  };

  class it_dynamic_entries
    : public Iterator<ELF_DynamicEntry,
                      LIEF::ELF::Binary::it_const_dynamic_entries> {
    public:
    it_dynamic_entries(const ELF_Binary::lief_t& src) :
      Iterator(src.dynamic_entries()) {}
    auto next() {
      return Iterator::next();
    }
    auto size() const {
      return Iterator::size();
    }
  };

  class it_dynamic_symbols
    : public Iterator<ELF_Symbol, LIEF::ELF::Binary::it_const_dynamic_symbols> {
    public:
    it_dynamic_symbols(const ELF_Binary::lief_t& src) :
      Iterator(src.dynamic_symbols()) {}
    auto next() {
      return Iterator::next();
    }
    auto size() const {
      return Iterator::size();
    }
  };

  class it_exported_symbols
    : public Iterator<ELF_Symbol, LIEF::ELF::Binary::it_const_exported_symbols> {
    public:
    it_exported_symbols(const ELF_Binary::lief_t& src) :
      Iterator(src.exported_symbols()) {}
    auto next() {
      return Iterator::next();
    }
    auto size() const {
      return Iterator::size();
    }
  };

  class it_imported_symbols
    : public Iterator<ELF_Symbol, LIEF::ELF::Binary::it_const_imported_symbols> {
    public:
    it_imported_symbols(const ELF_Binary::lief_t& src) :
      Iterator(src.imported_symbols()) {}
    auto next() {
      return Iterator::next();
    }
    auto size() const {
      return Iterator::size();
    }
  };

  class it_notes : public Iterator<ELF_Note, LIEF::ELF::Binary::it_const_notes> {
    public:
    it_notes(const ELF_Binary::lief_t& src) :
      Iterator(src.notes()) {}
    auto next() {
      return Iterator::next();
    }
    auto size() const {
      return Iterator::size();
    }
  };

  class it_symtab_symbols
    : public Iterator<ELF_Symbol, LIEF::ELF::Binary::it_const_symtab_symbols> {
    public:
    it_symtab_symbols(const ELF_Binary::lief_t& src) :
      Iterator(src.symtab_symbols()) {}
    auto next() {
      return Iterator::next();
    }
    auto size() const {
      return Iterator::size();
    }
  };

  class it_relocations
    : public Iterator<ELF_Relocation, LIEF::ELF::Binary::it_const_relocations> {
    public:
    it_relocations(const ELF_Binary::lief_t& src) :
      Iterator(src.relocations()) {}
    auto next() {
      return Iterator::next();
    }
    auto size() const {
      return Iterator::size();
    }
  };

  class it_pltgot_relocations
    : public Iterator<ELF_Relocation,
                      LIEF::ELF::Binary::it_const_pltgot_relocations> {
    public:
    it_pltgot_relocations(const ELF_Binary::lief_t& src) :
      Iterator(src.pltgot_relocations()) {}
    auto next() {
      return Iterator::next();
    }
    auto size() const {
      return Iterator::size();
    }
  };

  class it_dynamic_relocations
    : public Iterator<ELF_Relocation,
                      LIEF::ELF::Binary::it_const_dynamic_relocations> {
    public:
    it_dynamic_relocations(const ELF_Binary::lief_t& src) :
      Iterator(src.dynamic_relocations()) {}
    auto next() {
      return Iterator::next();
    }
    auto size() const {
      return Iterator::size();
    }
  };

  class it_object_relocations
    : public Iterator<ELF_Relocation,
                      LIEF::ELF::Binary::it_const_object_relocations> {
    public:
    it_object_relocations(const ELF_Binary::lief_t& src) :
      Iterator(src.object_relocations()) {}
    auto next() {
      return Iterator::next();
    }
    auto size() const {
      return Iterator::size();
    }
  };

  class it_symbols_version
    : public Iterator<ELF_SymbolVersion,
                      LIEF::ELF::Binary::it_const_symbols_version> {
    public:
    it_symbols_version(const ELF_Binary::lief_t& src) :
      Iterator(src.symbols_version()) {}
    auto next() {
      return Iterator::next();
    }
    auto size() const {
      return Iterator::size();
    }
  };

  class it_symbols_version_requirement
    : public Iterator<ELF_SymbolVersionRequirement,
                      LIEF::ELF::Binary::it_const_symbols_version_requirement> {
    public:
    it_symbols_version_requirement(const ELF_Binary::lief_t& src) :
      Iterator(src.symbols_version_requirement()) {}
    auto next() {
      return Iterator::next();
    }
    auto size() const {
      return Iterator::size();
    }
  };

  class it_symbols_version_definition
    : public Iterator<ELF_SymbolVersionDefinition,
                      LIEF::ELF::Binary::it_const_symbols_version_definition> {
    public:
    it_symbols_version_definition(const ELF_Binary::lief_t& src) :
      Iterator(src.symbols_version_definition()) {}
    auto next() {
      return Iterator::next();
    }
    auto size() const {
      return Iterator::size();
    }
  };

  class it_symbols
    : public Iterator<ELF_Symbol, LIEF::ELF::Binary::it_const_symbols> {
    public:
    it_symbols(const ELF_Binary::lief_t& src) :
      Iterator(src.symbols()) {}
    auto next() {
      return Iterator::next();
    }
    auto size() const {
      return Iterator::size();
    }
  };

  auto header() const {
    return std::make_unique<ELF_Header>(impl().header());
  }

  auto gnu_hash() const {
    return details::try_unique<ELF_GnuHash>(
        impl().gnu_hash()
    ); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto sysv_hash() const {
    return details::try_unique<ELF_SysvHash>(
        impl().sysv_hash()
    ); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
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

  auto remove_dynamic_entries_by_tag(uint64_t tag) {
    impl().remove(LIEF::ELF::DynamicEntry::TAG(tag));
  }

  auto remove_dynamic_entry(const ELF_DynamicEntry& entry) {
    impl().remove(entry.get());
  }

  auto remove_dynamic_entry_from_ptr(const LIEF::ELF::DynamicEntry* ptr) {
    assert(ptr != nullptr);
    impl().remove(*ptr);
  }

  auto add_dynamic_entry(const ELF_DynamicEntry& entry) {
    return std::make_unique<ELF_DynamicEntry>(impl().add(entry.get()));
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

  auto section_by_name(const std::string& name) const {
    return details::try_unique<ELF_Section>(impl().get_section(name));
  }

  auto relocation_by_addr(uint64_t addr) const {
    return details::try_unique<ELF_Relocation>(impl().get_relocation(addr));
  }

  auto relocation_for_symbol(const std::string& name) const {
    return details::try_unique<ELF_Relocation>(impl().get_relocation(name));
  }

  auto get_dynamic_symbol(const std::string& name) const {
    return details::try_unique<ELF_Symbol>(impl().get_dynamic_symbol(name));
  }

  auto get_symtab_symbol(const std::string& name) const {
    return details::try_unique<ELF_Symbol>(impl().get_symtab_symbol(name));
  }

  auto get_library(const std::string& name) const {
    return details::try_unique<ELF_DynamicEntryLibrary>(impl().get_library(name));
  }

  auto section_from_offset(uint64_t offset, bool skip_nobits) const {
    return details::try_unique<ELF_Section>(
        impl().section_from_offset(offset, skip_nobits)
    ); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto section_from_virtual_address(uint64_t address, bool skip_nobits) const {
    return details::try_unique<ELF_Section>(
        impl().section_from_virtual_address(address, skip_nobits)
    ); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto segment_from_virtual_address(uint64_t address) const {
    return details::try_unique<ELF_Segment>(
        impl().segment_from_virtual_address(address)
    ); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto segment_from_offset(uint64_t offset) const {
    return details::try_unique<ELF_Segment>(
        impl().segment_from_offset(offset)
    ); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  Span get_content_from_virtual_address(uint64_t virtual_address,
                                        uint64_t size) const {
    return make_span(impl().get_content_from_virtual_address(virtual_address,
                                                             size));
  }

  uint64_t virtual_address_to_offset(uint64_t virtual_address,
                                     uint32_t& error) const {
    return details::make_error<uint64_t>(
        impl().virtual_address_to_offset(virtual_address), error
    );
  }

  auto interpreter() const {
    return to_unique_string(impl().interpreter());
  }

  auto set_interpreter(const std::string& name) {
    impl().interpreter(name);
  }

  auto get_relocated_dynamic_array(uint64_t tag) const {
    return make_unique_vector<uint64_t>(
        impl().get_relocated_dynamic_array(LIEF::ELF::DynamicEntry::TAG(tag))
    );
  }

  auto is_targeting_android() const {
    return impl().is_targeting_android();
  }

  auto add_library(const std::string& library) {
    return std::make_unique<ELF_DynamicEntryLibrary>(impl().add_library(library));
  }

  auto functions() const {
    return std::make_unique<AbstractBinary::it_functions>(impl().functions());
  }

  auto dynamic_entry_by_tag(uint64_t tag) const {
    return details::try_unique<ELF_DynamicEntry>(
        impl().get((LIEF::ELF::DynamicEntry::TAG)tag)
    );
  }

  auto segment_by_type(uint64_t ty) const {
    return details::try_unique<ELF_Segment>(
        impl().get((LIEF::ELF::Segment::TYPE)ty)
    );
  }

  auto remove_library(const std::string& name) {
    impl().remove_library(name);
  }

  auto add_segment(const ELF_Segment& segment) {
    return details::try_unique<ELF_Segment>(impl().add(segment.get()));
  }

  auto find_version_requirement(const std::string& libname) const {
    return details::try_unique<ELF_SymbolVersionRequirement>(
        impl().find_version_requirement(libname)
    );
  }

  auto remove_version_requirement(const std::string& libname) {
    return impl().remove_version_requirement(libname);
  }

  auto remove_segment(const ELF_Segment& segment, bool clear) {
    impl().remove(segment.get(), clear);
  }

  auto remove_segments_by_type(uint64_t ty, bool clear) {
    impl().remove(LIEF::ELF::Segment::TYPE(ty), clear);
  }

  auto symbols() const {
    return std::make_unique<it_symbols>(impl());
  }

  auto strings(uint64_t min_size) const {
    return make_unique_vector<std::string>(impl().strings(min_size));
  }

  auto last_offset_section() const {
    return impl().last_offset_section();
  }
  auto last_offset_segment() const {
    return impl().last_offset_segment();
  }
  auto next_virtual_address() const {
    return impl().next_virtual_address();
  }
  auto eof_offset() const {
    return impl().eof_offset();
  }

  auto dtor_functions() const {
    return std::make_unique<AbstractBinary::it_functions>(impl().dtor_functions());
  }

  Span get_overlay() const {
    return make_span(impl().overlay());
  }

  auto set_overlay(const uint8_t* data, uint64_t size) {
    impl().overlay(std::vector<uint8_t>(data, data + size));
  }

  auto has_dynamic_entry_tag(uint64_t tag) const {
    return impl().has(LIEF::ELF::DynamicEntry::TAG(tag));
  }

  auto has_segment_type(uint64_t ty) const {
    return impl().has(LIEF::ELF::Segment::TYPE(ty));
  }

  auto has_note_type(uint32_t ty) const {
    return impl().has(LIEF::ELF::Note::TYPE(ty));
  }

  auto has_section_type(uint64_t ty) const {
    return impl().has(LIEF::ELF::Section::TYPE(ty));
  }

  auto get_note_by_type(uint32_t ty) const {
    return details::try_unique<ELF_Note>(impl().get(LIEF::ELF::Note::TYPE(ty)));
  }

  auto get_section_by_type(uint64_t ty) const {
    return details::try_unique<ELF_Section>(
        impl().get(LIEF::ELF::Section::TYPE(ty))
    );
  }

  auto has_section(const std::string& name) const {
    return impl().has_section(name);
  }

  auto has_section_with_offset(uint64_t offset) const {
    return impl().has_section_with_offset(offset);
  }

  auto has_section_with_va(uint64_t va) const {
    return impl().has_section_with_va(va);
  }

  auto has_library(const std::string& name) const {
    return impl().has_library(name);
  }

  auto has_dynamic_symbol(const std::string& name) const {
    return impl().has_dynamic_symbol(name);
  }

  auto has_symtab_symbol(const std::string& name) const {
    return impl().has_symtab_symbol(name);
  }

  int64_t dynsym_idx(const std::string& name) const {
    return impl().dynsym_idx(name);
  }

  int64_t symtab_idx(const std::string& name) const {
    return impl().symtab_idx(name);
  }

  auto patch_pltgot_by_name(const std::string& symbol_name, uint64_t address) {
    impl().patch_pltgot(symbol_name, address);
  }

  auto add_section(const ELF_Section& section, bool loaded, uint32_t pos) {
    return details::try_unique<ELF_Section>(
        impl().add(as<LIEF::ELF::Section>(&section), loaded,
                   LIEF::ELF::Binary::SEC_INSERT_POS(pos))
    );
  }

  auto add_note(const ELF_Note& note) {
    return std::make_unique<ELF_Note>(impl().add(note.get()));
  }

  auto add_dynamic_relocation(const ELF_Relocation& reloc) {
    return std::make_unique<ELF_Relocation>(
        impl().add_dynamic_relocation(as<LIEF::ELF::Relocation>(&reloc))
    );
  }

  auto add_pltgot_relocation(const ELF_Relocation& reloc) {
    return std::make_unique<ELF_Relocation>(
        impl().add_pltgot_relocation(as<LIEF::ELF::Relocation>(&reloc))
    );
  }

  auto add_symtab_symbol(const ELF_Symbol& symbol) {
    return std::make_unique<ELF_Symbol>(
        impl().add_symtab_symbol(as<LIEF::ELF::Symbol>(&symbol))
    );
  }

  auto add_dynamic_symbol(const ELF_Symbol& symbol) {
    return std::make_unique<ELF_Symbol>(
        impl().add_dynamic_symbol(as<LIEF::ELF::Symbol>(&symbol))
    );
  }

  auto add_exported_function(uint64_t address, const std::string& name) {
    return std::make_unique<ELF_Symbol>(impl().add_exported_function(address,
                                                                     name));
  }

  auto export_symbol_by_name(const std::string& symbol_name, uint64_t value) {
    return std::make_unique<ELF_Symbol>(impl().export_symbol(symbol_name, value));
  }

  auto export_symbol_obj(const ELF_Symbol& symbol) {
    return std::make_unique<ELF_Symbol>(
        impl().export_symbol(as<LIEF::ELF::Symbol>(&symbol))
    );
  }

  auto remove_symtab_symbol_by_name(const std::string& name) {
    impl().remove_symtab_symbol(name);
  }

  auto remove_dynamic_symbol_by_name(const std::string& name) {
    impl().remove_dynamic_symbol(name);
  }

  auto remove_section(const ELF_Section& section, bool clear) {
    impl().remove(as<LIEF::ELF::Section>(&section), clear);
  }

  auto remove_note(const ELF_Note& note) {
    impl().remove(note.get());
  }

  auto extend_segment(const ELF_Segment& segment, uint64_t size) {
    return details::try_unique<ELF_Segment>(impl().extend(segment.get(), size));
  }

  auto extend_section(const ELF_Section& section, uint64_t size) {
    return details::try_unique<ELF_Section>(
        impl().extend(as<LIEF::ELF::Section>(&section), size)
    );
  }

  auto strip() {
    impl().strip();
  }


  int64_t get_section_idx_by_name(const std::string& name) const {
    if (auto res = impl().get_section_idx(name)) {
      return static_cast<int64_t>(*res);
    }
    return -1;
  }

  int64_t get_section_idx_by_section(const ELF_Section& section) const {
    if (auto res = impl().get_section_idx(as<LIEF::ELF::Section>(&section))) {
      return *res;
    }
    return -1;
  }

  uint64_t relocate_phdr_table(uint32_t type) {
    return impl().relocate_phdr_table(LIEF::ELF::Binary::PHDR_RELOC(type));
  }

  auto write(const std::string& output) {
    impl().write(output);
  }
  void write_with_config(const std::string& output,
                         const ELF_Binary_write_config_t& config) {
    impl().write(output, LIEF::ELF::Builder::config_t{
                             config.dt_hash,
                             config.dyn_str,
                             config.dynamic_section,
                             config.fini_array,
                             config.gnu_hash,
                             config.init_array,
                             config.interpreter,
                             config.jmprel,
                             config.notes,
                             config.preinit_array,
                             config.relr,
                             config.android_rela,
                             config.rela,
                             config.static_symtab,
                             config.sym_verdef,
                             config.sym_verneed,
                             config.sym_versym,
                             config.symtab,
                             config.coredump_notes,
                             config.force_relocate,
                             config.keep_empty_version_requirement,
                         });
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
  lief_t& impl() {
    return as<lief_t>(this);
  }
};

using ELF_Binary_it_sections = ELF_Binary::it_sections;
using ELF_Binary_it_segments = ELF_Binary::it_segments;
using ELF_Binary_it_dynamic_entries = ELF_Binary::it_dynamic_entries;
using ELF_Binary_it_dynamic_symbols = ELF_Binary::it_dynamic_symbols;
using ELF_Binary_it_exported_symbols = ELF_Binary::it_exported_symbols;
using ELF_Binary_it_imported_symbols = ELF_Binary::it_imported_symbols;
using ELF_Binary_it_notes = ELF_Binary::it_notes;
using ELF_Binary_it_symtab_symbols = ELF_Binary::it_symtab_symbols;
using ELF_Binary_it_relocations = ELF_Binary::it_relocations;
using ELF_Binary_it_pltgot_relocations = ELF_Binary::it_pltgot_relocations;
using ELF_Binary_it_dynamic_relocations = ELF_Binary::it_dynamic_relocations;
using ELF_Binary_it_object_relocations = ELF_Binary::it_object_relocations;
using ELF_Binary_it_symbols_version = ELF_Binary::it_symbols_version;
using ELF_Binary_it_symbols_version_requirement =
    ELF_Binary::it_symbols_version_requirement;
using ELF_Binary_it_symbols_version_definition =
    ELF_Binary::it_symbols_version_definition;
using ELF_Binary_it_symbols = ELF_Binary::it_symbols;
