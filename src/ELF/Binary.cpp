/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include <algorithm>
#include <iterator>
#include <numeric>
#include <sstream>
#include <map>
#include <cctype>

#include "LIEF/DWARF/enums.hpp"

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#else
#define getpagesize() 0x1000
#endif

#include <stdexcept>

#include "logging.hpp"

#include "LIEF/exception.hpp"
#include "LIEF/utils.hpp"

#include "LIEF/BinaryStream/VectorStream.hpp"
#include "LIEF/BinaryStream/SpanStream.hpp"

#include "LIEF/ELF/utils.hpp"
#include "LIEF/ELF/EnumToString.hpp"
#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/DynamicEntry.hpp"
#include "LIEF/ELF/DynamicEntryLibrary.hpp"
#include "LIEF/ELF/DynamicEntryArray.hpp"
#include "LIEF/ELF/DynamicEntryFlags.hpp"
#include "LIEF/ELF/DynamicEntryRpath.hpp"
#include "LIEF/ELF/DynamicEntryRunPath.hpp"
#include "LIEF/ELF/DynamicSharedObject.hpp"
#include "LIEF/ELF/Note.hpp"
#include "LIEF/ELF/Builder.hpp"
#include "LIEF/ELF/Section.hpp"
#include "LIEF/ELF/Segment.hpp"
#include "LIEF/ELF/Relocation.hpp"
#include "LIEF/ELF/Symbol.hpp"
#include "LIEF/ELF/SymbolVersion.hpp"
#include "LIEF/ELF/SymbolVersionDefinition.hpp"
#include "LIEF/ELF/SymbolVersionRequirement.hpp"
#include "LIEF/ELF/GnuHash.hpp"
#include "LIEF/ELF/SysvHash.hpp"
#include "LIEF/ELF/hash.hpp"

#include "ELF/DataHandler/Handler.hpp"
#include "ELF/SizingInfo.hpp"

#include "Binary.tcc"
#include "Object.tcc"

namespace LIEF {
namespace ELF {

Binary::Binary() :
  sizing_info_{std::make_unique<sizing_info_t>()}
{
  format_ = LIEF::EXE_FORMATS::FORMAT_ELF;
}

Header& Binary::header() {
  return const_cast<Header&>(static_cast<const Binary*>(this)->header());
}

const Header& Binary::header() const {
  return header_;
}

ELF_CLASS Binary::type() const {
  return type_;
}

size_t Binary::hash(const std::string& name) {
  if (type_ == ELF_CLASS::ELFCLASS32) {
    return hash32(name.c_str());
  }
  return hash64(name.c_str());
}

LIEF::Binary::sections_t Binary::get_abstract_sections() {
  LIEF::Binary::sections_t sections;
  sections.reserve(sections_.size());
  std::transform(std::begin(sections_), std::end(sections_),
                 std::back_inserter(sections),
                 [] (const std::unique_ptr<Section>& s) {
                  return s.get();
                 });
  return sections;
}


// Sections
// ========

Binary::it_sections Binary::sections() {
  return sections_;
}


Binary::it_const_sections Binary::sections() const {
  return sections_;
}

// Segments
// ========

Binary::it_segments Binary::segments() {
  return segments_;
}

Binary::it_const_segments Binary::segments() const {
  return segments_;
}


LIEF::Binary::functions_t Binary::get_abstract_exported_functions() const {
  LIEF::Binary::functions_t result;
  for (const Symbol& symbol : exported_symbols()) {
    if (symbol.type() == ELF_SYMBOL_TYPES::STT_FUNC) {
      result.emplace_back(symbol.name(), symbol.value(), Function::flags_list_t{Function::FLAGS::EXPORTED});
    }
  }
  return result;
}


LIEF::Binary::functions_t Binary::get_abstract_imported_functions() const {
  LIEF::Binary::functions_t result;
  for (const Symbol& symbol : imported_symbols()) {
    if (symbol.type() == ELF_SYMBOL_TYPES::STT_FUNC) {
      result.emplace_back(symbol.name(), symbol.value(), Function::flags_list_t{Function::FLAGS::IMPORTED});
    }
  }
  return result;
}


std::vector<std::string> Binary::get_abstract_imported_libraries() const {
  std::vector<std::string> result;
  for (const DynamicEntry& entry : dynamic_entries()) {
    if (DynamicEntryLibrary::classof(&entry)) {
      result.push_back(entry.as<DynamicEntryLibrary>()->name());
    }
  }
  return result;
}


// Dynamic Entries
// ===============

Binary::it_dynamic_entries Binary::dynamic_entries() {
  return dynamic_entries_;
}

Binary::it_const_dynamic_entries Binary::dynamic_entries() const {
  return dynamic_entries_;
}


DynamicEntry& Binary::add(const DynamicEntry& entry) {

  std::unique_ptr<DynamicEntry> new_one;

  if (DynamicEntryLibrary::classof(&entry)) {
    new_one = std::make_unique<DynamicEntryLibrary>(*entry.as<const DynamicEntryLibrary>());
  }
  else if (DynamicSharedObject::classof(&entry)) {
    new_one = std::make_unique<DynamicSharedObject>(*entry.as<const DynamicSharedObject>());
  }
  else if (DynamicEntryRpath::classof(&entry)) {
    new_one = std::make_unique<DynamicEntryRpath>(*entry.as<const DynamicEntryRpath>());
  }
  else if (DynamicEntryRunPath::classof(&entry)) {
    new_one = std::make_unique<DynamicEntryRunPath>(*entry.as<const DynamicEntryRunPath>());
  }
  else if (DynamicEntryFlags::classof(&entry)) {
    new_one = std::make_unique<DynamicEntryFlags>(*entry.as<const DynamicEntryFlags>());
  }
  else if (DynamicEntryArray::classof(&entry)) {
    new_one = std::make_unique<DynamicEntryArray>(*entry.as<const DynamicEntryArray>());
  }
  else {
    new_one = std::make_unique<DynamicEntry>(entry);
  }

  const auto it_new_place = std::find_if(std::begin(dynamic_entries_), std::end(dynamic_entries_),
      [&new_one] (const std::unique_ptr<DynamicEntry>& e) {
        return e->tag() == new_one->tag() || e->tag() == DYNAMIC_TAGS::DT_NULL;
      });

  auto* ptr = new_one.get();
  dynamic_entries_.insert(it_new_place, std::move(new_one));
  return *ptr;

}


Note& Binary::add(const Note& note) {
  notes_.push_back(std::make_unique<Note>(note));
  return *notes_.back();
}


void Binary::remove(const DynamicEntry& entry) {
  const auto it_entry = std::find_if(std::begin(dynamic_entries_), std::end(dynamic_entries_),
      [&entry] (const std::unique_ptr<DynamicEntry>& e) {
        return *e == entry;
      });

  if (it_entry == std::end(dynamic_entries_)) {
    LIEF_WARN("Can't find {} in the dynamic table. This entry can't be removed", entry);
    return;
  }
  dynamic_entries_.erase(it_entry);
}


void Binary::remove(DYNAMIC_TAGS tag) {
  for (auto it = std::begin(dynamic_entries_); it != std::end(dynamic_entries_);) {
    if ((*it)->tag() == tag) {
      it = dynamic_entries_.erase(it);
    } else {
      ++it;
    }
  }
}

void Binary::remove(const Section& section, bool clear) {
  const auto it_section = std::find_if(std::begin(sections_), std::end(sections_),
      [&section] (const std::unique_ptr<Section>& s) {
        return *s == section;
      });

  if (it_section == std::end(sections_)) {
    LIEF_WARN("Can't find the section '{}'. It can't be removed!", section.name());
    return;
  }

  size_t idx = std::distance(std::begin(sections_), it_section);

  Section* s = it_section->get();

  // Remove from segments:
  for (std::unique_ptr<Segment>& segment : segments_) {
    auto& sections = segment->sections_;
    sections.erase(std::remove_if(std::begin(sections), std::end(sections),
                   [&s] (const Section* sec) { return *sec == *s; }), std::end(sections));
  }

  // Patch Section link
  for (std::unique_ptr<Section>& section : sections_) {
    if (section->link() == idx) {
      section->link(0);
      continue;
    }

    if (section->link() > idx) {
      section->link(section->link() - 1);
      continue;
    }
  }

  if (clear) {
    s->clear(0);
  }


  datahandler_->remove(s->file_offset(), s->size(), DataHandler::Node::SECTION);

  // Patch header
  header().numberof_sections(header().numberof_sections() - 1);

  if (idx < header().section_name_table_idx()) {
    header().section_name_table_idx(header().section_name_table_idx() - 1);
  }

  sections_.erase(it_section);
}

void Binary::remove(const Note& note) {
  const auto it_note = std::find_if(std::begin(notes_), std::end(notes_),
                                    [&note] (const std::unique_ptr<Note>& n) {
                                      return note == *n;
                                    });

  if (it_note == std::end(notes_)) {
    LIEF_WARN("Can't find the note with the type {}. It can't be removed!",
              to_string(static_cast<NOTE_TYPES>(note.type())));
    return;
  }
  notes_.erase(it_note);
}

void Binary::remove(NOTE_TYPES type) {
  for (auto it = std::begin(notes_); it != std::end(notes_);) {
    std::unique_ptr<Note>& n = *it;
    if (static_cast<NOTE_TYPES>(n->type()) == type) {
      n.reset(nullptr);
      it = notes_.erase(it);
    } else {
      ++it;
    }
  }
}



// Symbols
// =======

// Statics
// -------

Binary::it_static_symbols Binary::static_symbols() {
  return static_symbols_;
}

Binary::it_const_static_symbols Binary::static_symbols() const {
  return static_symbols_;
}

// Dynamics
// --------

Binary::it_dynamic_symbols Binary::dynamic_symbols() {
  return dynamic_symbols_;
}

Binary::it_const_dynamic_symbols Binary::dynamic_symbols() const {
  return dynamic_symbols_;
}


Binary::it_symbols Binary::symbols() {
  return static_dyn_symbols();
}

Binary::it_const_symbols Binary::symbols() const {
  return static_dyn_symbols();
}


Symbol& Binary::export_symbol(const Symbol& symbol) {

  // Check if the symbol is in the dynamic symbol table
  const auto it_symbol = std::find_if(std::begin(dynamic_symbols_), std::end(dynamic_symbols_),
                                      [&symbol] (const std::unique_ptr<Symbol>& s) {
                                        return *s == symbol;
                                      });
  Symbol* s = nullptr;
  if (it_symbol == std::end(dynamic_symbols_)) {
    // Create a new one
    const SymbolVersion& version = SymbolVersion::global();
    Symbol& new_sym = add_dynamic_symbol(symbol, &version);
    s = &new_sym;
  } else {
    s = it_symbol->get();
  }

  const auto it_text = std::find_if(std::begin(sections_), std::end(sections_),
                                    [] (const std::unique_ptr<Section>& s) {
                                      return s->name() == ".text";
                                    });

  size_t text_idx = std::distance(std::begin(sections_), it_text);

  if (s->binding() != SYMBOL_BINDINGS::STB_WEAK || s->binding() != SYMBOL_BINDINGS::STB_GLOBAL) {
    s->binding(SYMBOL_BINDINGS::STB_GLOBAL);
  }

  if (s->type() == ELF_SYMBOL_TYPES::STT_NOTYPE) {
    s->type(ELF_SYMBOL_TYPES::STT_COMMON);
  }

  if (s->shndx() == 0) {
    s->shndx(text_idx);
  }

  s->visibility(ELF_SYMBOL_VISIBILITY::STV_DEFAULT);
  return *s;
}

Symbol& Binary::export_symbol(const std::string& symbol_name, uint64_t value) {
  Symbol* s = get_dynamic_symbol(symbol_name);
  if (s != nullptr) {
    if (value > 0) {
      s->value(value);
    }
    return export_symbol(*s);
  }

  s = get_static_symbol(symbol_name);
  if (s != nullptr) {
    if (value > 0) {
      s->value(value);
    }
    return export_symbol(*s);
  }

  // Create a new one
  Symbol newsym;
  newsym.name(symbol_name);
  newsym.type(ELF_SYMBOL_TYPES::STT_COMMON);
  newsym.binding(SYMBOL_BINDINGS::STB_GLOBAL);
  newsym.visibility(ELF_SYMBOL_VISIBILITY::STV_DEFAULT);
  newsym.value(value);
  newsym.size(0x10);
  return export_symbol(newsym);
}


Symbol& Binary::add_exported_function(uint64_t address, const std::string& name) {
  std::string funcname = name;
  if (funcname.empty()) {
    std::stringstream ss;
    ss << "func_" << std::hex << address;
    funcname = ss.str();
  }

  // First: Check if a symbol with the given 'name' exists in the **dynamic** table
  Symbol* s = get_dynamic_symbol(funcname);
  if (s != nullptr) {
    s->type(ELF_SYMBOL_TYPES::STT_FUNC);
    s->binding(SYMBOL_BINDINGS::STB_GLOBAL);
    s->visibility(ELF_SYMBOL_VISIBILITY::STV_DEFAULT);
    s->value(address);
    return export_symbol(*s);
  }

  // Second: Check if a symbol with the given 'name' exists in the **static**
  s = get_static_symbol(funcname);
  if (s != nullptr) {
    s->type(ELF_SYMBOL_TYPES::STT_FUNC);
    s->binding(SYMBOL_BINDINGS::STB_GLOBAL);
    s->visibility(ELF_SYMBOL_VISIBILITY::STV_DEFAULT);
    s->value(address);
    return export_symbol(*s);
  }

  // Create a new Symbol
  Symbol funcsym;
  funcsym.name(funcname);
  funcsym.type(ELF_SYMBOL_TYPES::STT_FUNC);
  funcsym.binding(SYMBOL_BINDINGS::STB_GLOBAL);
  funcsym.visibility(ELF_SYMBOL_VISIBILITY::STV_DEFAULT);
  funcsym.value(address);
  funcsym.size(0x10);

  return export_symbol(funcsym);

}


bool Binary::has_dynamic_symbol(const std::string& name) const {
  const auto it_symbol = std::find_if(std::begin(dynamic_symbols_), std::end(dynamic_symbols_),
                                      [&name] (const std::unique_ptr<Symbol>& s) {
                                        return s->name() == name;
                                      });

  return it_symbol != std::end(dynamic_symbols_);
}

const Symbol* Binary::get_dynamic_symbol(const std::string& name) const {
  const auto it_symbol = std::find_if(std::begin(dynamic_symbols_), std::end(dynamic_symbols_),
                                      [&name] (const std::unique_ptr<Symbol>& s) {
                                        return s->name() == name;
                                      });
  if (it_symbol == std::end(dynamic_symbols_)) {
    return nullptr;
  }
  return it_symbol->get();
}

Symbol* Binary::get_dynamic_symbol(const std::string& name) {
  return const_cast<Symbol*>(static_cast<const Binary*>(this)->get_dynamic_symbol(name));
}

bool Binary::has_static_symbol(const std::string& name) const {
  const auto it_symbol = std::find_if(std::begin(static_symbols_), std::end(static_symbols_),
                                      [&name] (const std::unique_ptr<Symbol>& s) {
                                        return s->name() == name;
                                      });
  return it_symbol != std::end(static_symbols_);
}

const Symbol* Binary::get_static_symbol(const std::string& name) const {
  const auto it_symbol = std::find_if(std::begin(static_symbols_), std::end(static_symbols_),
                                      [&name] (const std::unique_ptr<Symbol>& s) {
                                        return s->name() == name;
                                      });
  if (it_symbol == std::end(static_symbols_)) {
    return nullptr;
  }
  return it_symbol->get();
}


Binary::string_list_t Binary::strings(size_t min_size) const {
  Binary::string_list_t list;
  const Section* rodata = get_section(".rodata");
  if (rodata == nullptr) {
    return {};
  }

  span<const uint8_t> data = rodata->content();
  std::string current;
  current.reserve(100);

  for (size_t i = 0; i < data.size(); ++i) {
    char c = static_cast<char>(data[i]);

    // Terminator
    if (c == '\0') {
      if (current.size() >= min_size) {
        list.push_back(current);
        current.clear();
        continue;
      }
      current.clear();
      continue;
    }

    // Valid char
    if (std::isprint(c) == 0) {
      current.clear();
      continue;
    }

    current.push_back(c);
  }


  return list;
}

Symbol* Binary::get_static_symbol(const std::string& name) {
  return const_cast<Symbol*>(static_cast<const Binary*>(this)->get_static_symbol(name));
}


std::vector<Symbol*> Binary::static_dyn_symbols() const {
  std::vector<Symbol*> symbols;
  symbols.reserve(static_symbols_.size() + dynamic_symbols_.size());
  for (const std::unique_ptr<Symbol>& s : dynamic_symbols_) {
    symbols.push_back(s.get());
  }

  for (const std::unique_ptr<Symbol>& s : static_symbols_) {
    symbols.push_back(s.get());
  }
  return symbols;
}

// Exported
// --------

Binary::it_exported_symbols Binary::exported_symbols() {

  return {static_dyn_symbols(), [] (const Symbol* symbol) {
    return symbol->is_exported();
  }};
}

Binary::it_const_exported_symbols Binary::exported_symbols() const {
  return {static_dyn_symbols(), [] (const Symbol* symbol) {
    return symbol->is_exported();
  }};
}



// Imported
// --------

Binary::it_imported_symbols Binary::imported_symbols() {
  return {static_dyn_symbols(), [] (const Symbol* symbol) {
    return symbol->is_imported();
  }};
}

Binary::it_const_imported_symbols Binary::imported_symbols() const {
  return {static_dyn_symbols(), [] (const Symbol* symbol) {
    return symbol->is_imported();
  }};
}


// Symbol version
// --------------

Binary::it_symbols_version Binary::symbols_version() {
  return symbol_version_table_;
}

Binary::it_const_symbols_version Binary::symbols_version() const {
  return symbol_version_table_;
}

// Symbol version definition
// -------------------------

Binary::it_symbols_version_definition Binary::symbols_version_definition() {
  return symbol_version_definition_;
}

Binary::it_const_symbols_version_definition Binary::symbols_version_definition() const {
  return symbol_version_definition_;
}

// Symbol version requirement
// --------------------------

Binary::it_symbols_version_requirement Binary::symbols_version_requirement() {
  return symbol_version_requirements_;
}

Binary::it_const_symbols_version_requirement Binary::symbols_version_requirement() const {
  return symbol_version_requirements_;
}

void Binary::remove_symbol(const std::string& name) {
  remove_static_symbol(name);
  remove_dynamic_symbol(name);
}


void Binary::remove_static_symbol(const std::string& name) {
  Symbol* sym = get_static_symbol(name);
  if (sym == nullptr) {
    LIEF_WARN("Can't find the static symbol '{}'. It won't be removed", name);
    return;
  }
  remove_static_symbol(sym);
}

void Binary::remove_static_symbol(Symbol* symbol) {
  if (symbol == nullptr) {
    return;
  }

  const auto it_symbol = std::find_if(std::begin(static_symbols_), std::end(static_symbols_),
                                      [symbol] (const std::unique_ptr<Symbol>& sym) {
                                        return *symbol == *sym;
                                      });

  if (it_symbol == std::end(static_symbols_)) {
    LIEF_WARN("Can't find the static symbol '{}'. It won't be removed", symbol->name());
    return;
  }

  static_symbols_.erase(it_symbol);
}



void Binary::remove_dynamic_symbol(const std::string& name) {
  Symbol* sym = get_dynamic_symbol(name);
  if (sym == nullptr) {
    LIEF_WARN("Can't find the dynamic symbol '{}'. It won't be removed", name);
    return;
  }
  remove_dynamic_symbol(sym);
}

void Binary::remove_dynamic_symbol(Symbol* symbol) {
  if (symbol == nullptr) {
    return;
  }
  const auto it_symbol = std::find_if(std::begin(dynamic_symbols_), std::end(dynamic_symbols_),
                                      [symbol] (const std::unique_ptr<Symbol>& sym) {
                                        return *symbol == *sym;
                                      });

  if (it_symbol == std::end(dynamic_symbols_)) {
    LIEF_WARN("Can't find the dynamic symbol '{}'. It won't be removed", symbol->name());
    return;
  }


  // Update relocations
  auto it_relocation = std::find_if(std::begin(relocations_), std::end(relocations_),
      [symbol] (const std::unique_ptr<Relocation>& relocation) {
        return relocation->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_PLTGOT &&
               relocation->has_symbol() && relocation->symbol() == symbol;
      });

  if (it_relocation != std::end(relocations_)) {
    relocations_.erase(it_relocation);
  }


  it_relocation = std::find_if(std::begin(relocations_), std::end(relocations_),
      [symbol] (const std::unique_ptr<Relocation>& relocation) {
        return relocation->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_DYNAMIC &&
               relocation->has_symbol() && relocation->symbol() == symbol;
      });

  if (it_relocation != std::end(relocations_)) {
    relocations_.erase(it_relocation);
  }

  // Update symbol versions
  if (symbol->has_version()) {
    const auto it = std::find_if(std::begin(symbol_version_table_), std::end(symbol_version_table_),
                                 [symbol] (const std::unique_ptr<SymbolVersion>& sv) {
                                   return sv.get() == symbol->symbol_version_;
                                 });
    if (it != std::end(symbol_version_table_)) {
      symbol_version_table_.erase(it);
    }
  }

  dynamic_symbols_.erase(it_symbol);
}


// Relocations
// ===========

// Dynamics
// --------

Binary::it_dynamic_relocations Binary::dynamic_relocations() {
  return {relocations_, [] (const std::unique_ptr<Relocation>& reloc) {
      return reloc->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_DYNAMIC;
    }
  };
}

Binary::it_const_dynamic_relocations Binary::dynamic_relocations() const {
  return {relocations_, [] (const std::unique_ptr<Relocation>& reloc) {
      return reloc->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_DYNAMIC;
    }
  };
}

Relocation& Binary::add_dynamic_relocation(const Relocation& relocation) {
  auto relocation_ptr = std::make_unique<Relocation>(relocation);
  relocation_ptr->purpose(RELOCATION_PURPOSES::RELOC_PURPOSE_DYNAMIC);
  relocation_ptr->architecture_ = header().machine_type();

  // Add symbol
  const Symbol* associated_sym = relocation.symbol();
  if (associated_sym != nullptr) {
    Symbol* inner_sym = get_dynamic_symbol(associated_sym->name());
    if (inner_sym == nullptr) {
      inner_sym = &(add_dynamic_symbol(*associated_sym));
    }
    const auto it_sym = std::find_if(std::begin(dynamic_symbols_), std::end(dynamic_symbols_),
                                    [inner_sym] (const std::unique_ptr<Symbol>& s) {
                                      return s->name() == inner_sym->name();
                                    });
    const size_t idx = std::distance(std::begin(dynamic_symbols_), it_sym);
    relocation_ptr->info(idx);
    relocation_ptr->symbol(inner_sym);
  }

  // Update the Dynamic Section (Thanks to @yd0b0N)
  bool is_rela = relocation.is_rela();
  DYNAMIC_TAGS tag_sz  = is_rela ? DYNAMIC_TAGS::DT_RELASZ  : DYNAMIC_TAGS::DT_RELSZ;
  DYNAMIC_TAGS tag_ent = is_rela ? DYNAMIC_TAGS::DT_RELAENT : DYNAMIC_TAGS::DT_RELENT;

  DynamicEntry* dt_sz  = get(tag_sz);
  DynamicEntry* dt_ent = get(tag_ent);
  if (dt_sz != nullptr && dt_ent != nullptr) {
    dt_sz->value(dt_sz->value() + dt_ent->value());
  }

  relocations_.push_back(std::move(relocation_ptr));
  return *relocations_.back();
}


Relocation& Binary::add_pltgot_relocation(const Relocation& relocation) {
  auto relocation_ptr = std::make_unique<Relocation>(relocation);
  relocation_ptr->purpose(RELOCATION_PURPOSES::RELOC_PURPOSE_PLTGOT);
  relocation_ptr->architecture_ = header().machine_type();

  // Add symbol
  const Symbol* associated_sym = relocation.symbol();
  if (associated_sym != nullptr) {
    Symbol* inner_sym = get_dynamic_symbol(associated_sym->name());
    if (inner_sym == nullptr) {
      inner_sym = &(add_dynamic_symbol(*associated_sym));
    }
    const auto it_sym = std::find_if(std::begin(dynamic_symbols_), std::end(dynamic_symbols_),
                                     [inner_sym] (const std::unique_ptr<Symbol>& s) {
                                      return s->name() == inner_sym->name();
                                     });
    const size_t idx = std::distance(std::begin(dynamic_symbols_), it_sym);
    relocation_ptr->info(idx);
    relocation_ptr->symbol(inner_sym);
  }

  // Update the Dynamic Section
  const bool is_rela = relocation.is_rela();
  const bool is64    = (type() == ELF_CLASS::ELFCLASS64);

  size_t reloc_size = 0;
  if (is_rela) {
    if (is64) {
      reloc_size = sizeof(details::Elf64_Rela);
    } else {
      reloc_size = sizeof(details::Elf32_Rela);
    }
  } else {
    if (is64) {
      reloc_size = sizeof(details::Elf64_Rel);
    } else {
      reloc_size = sizeof(details::Elf32_Rel);
    }
  }

  DynamicEntry* dt_sz = get(DYNAMIC_TAGS::DT_PLTRELSZ);
  if (dt_sz != nullptr && has(DYNAMIC_TAGS::DT_JMPREL)) {
    dt_sz->value(dt_sz->value() + reloc_size);
  }

  relocations_.push_back(std::move(relocation_ptr));
  return *relocations_.back();
}

Relocation* Binary::add_object_relocation(const Relocation& relocation, const Section& section) {
  const auto it_section = std::find_if(std::begin(sections_), std::end(sections_),
      [&section] (const std::unique_ptr<Section>& sec) {
        return &section == sec.get();
      });

  if (it_section == std::end(sections_)) {
    LIEF_ERR("Can't find section '{}'", section.name());
    return nullptr;
  }


  auto relocation_ptr = std::make_unique<Relocation>(relocation);
  relocation_ptr->purpose(RELOCATION_PURPOSES::RELOC_PURPOSE_OBJECT);
  relocation_ptr->architecture_ = header().machine_type();
  relocation_ptr->section_ = it_section->get();
  relocations_.push_back(std::move(relocation_ptr));
  return relocations_.back().get();
}

// plt/got
// -------
Binary::it_pltgot_relocations Binary::pltgot_relocations() {
  return {relocations_, [] (const std::unique_ptr<Relocation>& reloc) {
      return reloc->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_PLTGOT;
    }
  };
}

Binary::it_const_pltgot_relocations Binary::pltgot_relocations() const {
  return {relocations_, [] (const std::unique_ptr<Relocation>& reloc) {
      return reloc->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_PLTGOT;
    }
  };
}


// objects
// -------
Binary::it_object_relocations Binary::object_relocations() {
  return {relocations_, [] (const std::unique_ptr<Relocation>& reloc) {
      return reloc->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_OBJECT;
    }
  };
}

Binary::it_const_object_relocations Binary::object_relocations() const {
  return {relocations_, [] (const std::unique_ptr<Relocation>& reloc) {
      return reloc->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_OBJECT;
    }
  };
}

// All relocations
// ---------------
Binary::it_relocations Binary::relocations() {
  return relocations_;
}

Binary::it_const_relocations Binary::relocations() const {
  return relocations_;
}

LIEF::Binary::relocations_t Binary::get_abstract_relocations() {
  LIEF::Binary::relocations_t relocations;
  relocations.reserve(relocations_.size());
  std::transform(std::begin(relocations_), std::end(relocations_),
                 std::back_inserter(relocations),
                 [] (const std::unique_ptr<Relocation>& r) {
                  return r.get();
                 });

  return relocations;
}


LIEF::Binary::symbols_t Binary::get_abstract_symbols() {
  LIEF::Binary::symbols_t symbols;
  symbols.reserve(dynamic_symbols_.size() + static_symbols_.size());
  std::transform(std::begin(dynamic_symbols_), std::end(dynamic_symbols_),
                 std::back_inserter(symbols),
                 [] (std::unique_ptr<Symbol>& s) {
                  return s.get();
                 });

  std::transform(std::begin(static_symbols_), std::end(static_symbols_),
                 std::back_inserter(symbols),
                 [] (std::unique_ptr<Symbol>& s) {
                  return s.get();
                 });

  return symbols;

}


Section* Binary::get_section(const std::string& name) {
  return const_cast<Section*>(static_cast<const Binary*>(this)->get_section(name));
}

const Section* Binary::get_section(const std::string& name) const {
  const auto it_section = std::find_if(std::begin(sections_), std::end(sections_),
                                       [&name] (const std::unique_ptr<Section>& section) {
                                         return section->name() == name;
                                       });

  if (it_section == std::end(sections_)) {
    return nullptr;
  }
  return it_section->get();
}

Section* Binary::text_section() {
  return get_section(".text");
}


Section* Binary::dynamic_section() {
  const auto it_dynamic_section = std::find_if(std::begin(sections_), std::end(sections_),
                                               [] (const std::unique_ptr<Section>& section) {
                                                  return section->type() == ELF_SECTION_TYPES::SHT_DYNAMIC;
                                               });

  if (it_dynamic_section == std::end(sections_)) {
    return nullptr;
  }

  return it_dynamic_section->get();

}

Section* Binary::hash_section() {
  const auto it_hash_section = std::find_if(std::begin(sections_), std::end(sections_),
      [] (const std::unique_ptr<Section>& section) {
        return section->type() == ELF_SECTION_TYPES::SHT_HASH ||
               section->type() == ELF_SECTION_TYPES::SHT_GNU_HASH;
      });

  if (it_hash_section == std::end(sections_)) {
    return nullptr;
  }

  return it_hash_section->get();

}

Section* Binary::static_symbols_section() {
  const auto it_symtab_section = std::find_if(std::begin(sections_), std::end(sections_),
                                              [] (const std::unique_ptr<Section>& section) {
                                                return section->type() == ELF_SECTION_TYPES::SHT_SYMTAB;
                                              });


  if (it_symtab_section == std::end(sections_)) {
    return nullptr;
  }

  return it_symtab_section->get();
}

uint64_t Binary::imagebase() const {
  auto imagebase = static_cast<uint64_t>(-1);
  for (const std::unique_ptr<Segment>& segment : segments_) {
    if (segment != nullptr && segment->type() == SEGMENT_TYPES::PT_LOAD) {
      imagebase = std::min(imagebase, segment->virtual_address() - segment->file_offset());
    }
  }
  return imagebase;
}

uint64_t Binary::virtual_size() const {
  uint64_t virtual_size = 0;
  for (const std::unique_ptr<Segment>& segment : segments_) {
    if (segment != nullptr && segment->type() == SEGMENT_TYPES::PT_LOAD) {
      virtual_size = std::max(virtual_size, segment->virtual_address() + segment->virtual_size());
    }
  }
  virtual_size = align(virtual_size, static_cast<uint64_t>(getpagesize()));
  return virtual_size - imagebase();
}


std::vector<uint8_t> Binary::raw() {
  Builder builder{*this};
  builder.build();
  return builder.get_build();
}


result<uint64_t> Binary::get_function_address(const std::string& func_name) const {
  if (auto res = get_function_address(func_name, /* demangle */true)) {
    return *res;
  }

  if (auto res = get_function_address(func_name, /* demangle */false)) {
    return *res;
  }

  return make_error_code(lief_errors::not_found);
}

result<uint64_t> Binary::get_function_address(const std::string& func_name, bool demangled) const {
  const auto it_symbol = std::find_if(std::begin(static_symbols_), std::end(static_symbols_),
      [&func_name, demangled] (const std::unique_ptr<Symbol>& symbol) {
        std::string sname;
        if (demangled) {
          sname = symbol->demangled_name();
        }

        if (sname.empty()) {
          sname = symbol->name();
        }
        return sname == func_name &&
               symbol->type() == ELF_SYMBOL_TYPES::STT_FUNC;
      });

  if (it_symbol == std::end(static_symbols_)) {
    return make_error_code(lief_errors::not_found);
  }

  return (*it_symbol)->value();
}

Section* Binary::add(const Section& section, bool loaded) {
  if (section.is_frame()) {
    return add_frame_section(section);
  }
  if (loaded) {
    return add_section<true>(section);
  }
  return add_section<false>(section);
}


Section* Binary::add_frame_section(const Section& sec) {
  auto new_section = std::make_unique<Section>(sec);
  this->header().numberof_sections(this->header().numberof_sections() + 1);
  this->sections_.push_back(std::move(new_section));
  return this->sections_.back().get();
}

bool Binary::is_pie() const {
  const auto it_segment = std::find_if(std::begin(segments_), std::end(segments_),
                                       [] (const std::unique_ptr<Segment>& entry) {
                                         return entry->type() == SEGMENT_TYPES::PT_INTERP;
                                       });
  if (header().file_type() != E_TYPE::ET_DYN) {
    return false;
  }

  /* If the ELF binary uses an interpreter, then it is position
   * independant since the interpreter aims at loading the binary at a random base address
   */
  if (it_segment != std::end(segments_)) {
    return true;
  }
  /* It also exists ELF executables which don't have PT_INTERP but are
   * PIE (see: https://github.com/lief-project/LIEF/issues/747). That's
   * the case, for instance, when compiling with the -static-pie flag
   *
   * While header().file_type() == E_TYPE::ET_DYN is a requirement
   * for PIC binary (Position independant **CODE**), it does not enable
   * to distinguish PI **Executables** from libraries.
   *
   * Therefore, we add the following checks:
   * 1. The binary embeds a PT_DYNAMIC segment
   * 2. The dynamic table contains a DT_FLAGS_1 set with PIE
   */


  if (has(SEGMENT_TYPES::PT_DYNAMIC)) {
    if (const auto* flag = static_cast<const DynamicEntryFlags*>(get(DYNAMIC_TAGS::DT_FLAGS_1))) {
      return flag->has(DYNAMIC_FLAGS_1::DF_1_PIE);
    }
  }

  return false;
}


bool Binary::has_nx() const {
  const auto it_stack = std::find_if(std::begin(segments_), std::end(segments_),
                                     [] (const std::unique_ptr<Segment>& segment) {
                                       return segment->type() == SEGMENT_TYPES::PT_GNU_STACK;
                                     });
  if (it_stack == std::end(segments_)) {
    if (header().machine_type() == ARCH::EM_PPC64) {
      // The PPC64 ELF ABI has a non-executable stack by default.
      return true;
    } else {
      return false;
    }
  }

  return !(*it_stack)->has(ELF_SEGMENT_FLAGS::PF_X);

}

Segment* Binary::add(const Segment& segment, uint64_t base) {
  const uint64_t new_base = base == 0 ? next_virtual_address() : base;

  switch(header().file_type()) {
    case E_TYPE::ET_EXEC: return add_segment<E_TYPE::ET_EXEC>(segment, new_base);
    case E_TYPE::ET_DYN:  return add_segment<E_TYPE::ET_DYN>(segment, new_base);
    default:
      {
        LIEF_WARN("Adding segment for {} is not implemented", to_string(header().file_type()));
        return nullptr;
      }
  }
}


Segment* Binary::replace(const Segment& new_segment, const Segment& original_segment, uint64_t base) {

  const auto it_original_segment = std::find_if(std::begin(segments_), std::end(segments_),
                                    [&original_segment] (const std::unique_ptr<Segment>& s) { return *s == original_segment; });

  if (it_original_segment == std::end(segments_)) {
    LIEF_WARN("Unable to find the segment in the current binary");
    return nullptr;
  }


  uint64_t new_base = base;

  if (new_base == 0) {
    new_base = next_virtual_address();
  }

  span<const uint8_t> content_ref = new_segment.content();
  std::vector<uint8_t> content{content_ref.data(), std::end(content_ref)};

  auto new_segment_ptr = std::make_unique<Segment>(new_segment);
  new_segment_ptr->datahandler_ = datahandler_.get();

  DataHandler::Node new_node{new_segment_ptr->file_offset(), new_segment_ptr->physical_size(),
                             DataHandler::Node::SEGMENT};
  datahandler_->add(new_node);
  new_segment_ptr->handler_size_ = new_segment_ptr->physical_size();

  const uint64_t last_offset_sections = last_offset_section();
  const uint64_t last_offset_segments = last_offset_segment();
  const uint64_t last_offset          = std::max<uint64_t>(last_offset_sections, last_offset_segments);

  const auto psize = static_cast<uint64_t>(getpagesize());
  const uint64_t last_offset_aligned = align(last_offset, psize);
  new_segment_ptr->file_offset(last_offset_aligned);

  if (new_segment_ptr->virtual_address() == 0) {
    new_segment_ptr->virtual_address(new_base + last_offset_aligned);
  }

  new_segment_ptr->physical_address(new_segment_ptr->virtual_address());

  uint64_t segmentsize = align(content.size(), psize);
  content.resize(segmentsize);

  new_segment_ptr->physical_size(segmentsize);
  new_segment_ptr->virtual_size(segmentsize);

  if (new_segment_ptr->alignment() == 0) {
    new_segment_ptr->alignment(psize);
  }

  auto alloc = datahandler_->make_hole(last_offset_aligned, new_segment_ptr->physical_size());
  if (!alloc) {
    LIEF_ERR("Allocation failed");
    return nullptr;
  }
  new_segment_ptr->content(content);


  const auto it_segment_phdr = std::find_if(std::begin(segments_), std::end(segments_),
                                            [] (const std::unique_ptr<Segment>& s) {
                                              return s->type() == SEGMENT_TYPES::PT_PHDR;
                                            });

  if (it_segment_phdr != std::end(segments_)) {
    std::unique_ptr<Segment>& phdr_segment = *it_segment_phdr;
    const size_t phdr_size = phdr_segment->content().size();
    phdr_segment->content(std::vector<uint8_t>(phdr_size, 0));
  }

  // Remove
  std::unique_ptr<Segment> local_original_segment = std::move(*it_original_segment);
  datahandler_->remove(local_original_segment->file_offset(), local_original_segment->physical_size(), DataHandler::Node::SEGMENT);
  segments_.erase(it_original_segment);

  // Patch shdr
  Header& header = this->header();
  const uint64_t new_section_hdr_offset = new_segment_ptr->file_offset() + new_segment_ptr->physical_size();
  header.section_headers_offset(new_section_hdr_offset);

  Segment* seg = new_segment_ptr.get();
  segments_.push_back(std::move(new_segment_ptr));
  return seg;
}


void Binary::remove(const Segment& segment) {
  const auto it_segment = std::find_if(std::begin(segments_), std::end(segments_),
                                       [&segment] (const std::unique_ptr<Segment>& s) {
                                          return *s == segment;
                                       });

  if (it_segment == std::end(segments_)) {
    LIEF_ERR("Can't find the provided segment");
    return;
  }

  std::unique_ptr<Segment> local_segment = std::move(*it_segment);
  datahandler_->remove(local_segment->file_offset(), local_segment->physical_size(),
                       DataHandler::Node::SEGMENT);
  if (phdr_reloc_info_.new_offset > 0) {
    ++phdr_reloc_info_.nb_segments;
  }
  header().numberof_segments(header().numberof_segments() - 1);

  segments_.erase(it_segment);
}


Segment* Binary::extend(const Segment& segment, uint64_t size) {
  const SEGMENT_TYPES type = segment.type();
  switch (type) {
    case SEGMENT_TYPES::PT_PHDR:
    case SEGMENT_TYPES::PT_LOAD:
      {
        return extend_segment<SEGMENT_TYPES::PT_LOAD>(segment, size);
      }

    default:
      {
        LIEF_WARN("Extending segment '{}' is not supported");
        return nullptr;
      }
  }
}


Section* Binary::extend(const Section& section, uint64_t size) {
  const auto it_section = std::find_if(std::begin(sections_), std::end(sections_),
                                       [&section] (const std::unique_ptr<Section>& s) {
                                         return *s == section;
                                       });

  if (it_section == std::end(sections_)) {
    LIEF_WARN("Unable to find the section '{}' in the current binary", section.name());
    return nullptr;
  }


  std::unique_ptr<Section>& section_to_extend = *it_section;

  uint64_t from_offset  = section_to_extend->offset() + section_to_extend->size();
  uint64_t from_address = section_to_extend->virtual_address() + section_to_extend->size();
  bool section_loaded   = section_to_extend->virtual_address() != 0;
  uint64_t shift        = size;

  auto alloc = datahandler_->make_hole(section_to_extend->offset() + section_to_extend->size(),size);

  if (!alloc) {
    LIEF_ERR("Allocation failed");
    return nullptr;
  }

  shift_sections(from_offset, shift);
  shift_segments(from_offset, shift);


  // Patch segment size for the segment which contains the new segment
  for (std::unique_ptr<Segment>& segment : segments_) {
    if ((segment->file_offset() + segment->physical_size()) >= from_offset &&
        from_offset >= segment->file_offset()) {
      if (section_loaded) {
        segment->virtual_size(segment->virtual_size() + shift);
      }
      segment->physical_size(segment->physical_size() + shift);
    }
  }


  section_to_extend->size(section_to_extend->size() + size);

  span<const uint8_t> content_ref = section_to_extend->content();
  std::vector<uint8_t> content    = {std::begin(content_ref), std::end(content_ref)};
  content.resize(section_to_extend->size(), 0);
  section_to_extend->content(content);


  header().section_headers_offset(header().section_headers_offset() + shift);

  if (section_loaded) {
    shift_dynamic_entries(from_address, shift);
    shift_symbols(from_address, shift);
    shift_relocations(from_address, shift);

    if (type() == ELF_CLASS::ELFCLASS32) {
      fix_got_entries<details::ELF32>(from_address, shift);
    } else {
      fix_got_entries<details::ELF64>(from_address, shift);
    }


    if (header().entrypoint() >= from_address) {
      header().entrypoint(header().entrypoint() + shift);
    }
  }

  return section_to_extend.get();
}

// Patch
// =====

void Binary::patch_address(uint64_t address, const std::vector<uint8_t>& patch_value, LIEF::Binary::VA_TYPES) {

  // Object file does not have segments
  if (header().file_type() == E_TYPE::ET_REL) {
    Section* section = section_from_offset(address);
    if (section == nullptr) {
      LIEF_ERR("Can't find a section associated with the virtual address 0x{:x}", address);
      return;
    }
    span<uint8_t> content = section->writable_content();
    const uint64_t offset = address - section->file_offset();

    if (offset + patch_value.size() > content.size()) {
      LIEF_ERR("The patch value ({} bytes @0x{:x}) is out of bounds of the segment (limit: 0x{:x})",
               patch_value.size(), offset, content.size());
      return;
    }
    std::copy(std::begin(patch_value), std::end(patch_value),
              content.data() + offset);
    return;
  }

  // Find the segment associated with the virtual address
  Segment* segment_topatch = segment_from_virtual_address(address);
  if (segment_topatch == nullptr) {
    LIEF_ERR("Can't find a segment associated with the virtual address 0x{:x}", address);
    return;
  }
  const uint64_t offset = address - segment_topatch->virtual_address();
  span<uint8_t> content_ref = segment_topatch->writable_content();

  if (offset + patch_value.size() > content_ref.size()) {
    LIEF_ERR("The patch value ({} bytes @0x{:x}) is out of bounds of the segment (limit: 0x{:x})",
             patch_value.size(), offset, content_ref.size());
    return;
  }
  std::copy(std::begin(patch_value), std::end(patch_value),
            content_ref.data() + offset);
}


void Binary::patch_address(uint64_t address, uint64_t patch_value, size_t size, LIEF::Binary::VA_TYPES) {
  if (size > sizeof(patch_value)) {
    LIEF_ERR("The size of the patch value (0x{:x}) is larger that sizeof(uint64_t) which is not supported",
             size);
    return;
  }

  // Object file does not have segments
  if (header().file_type() == E_TYPE::ET_REL) {
    Section* section = section_from_offset(address);
    if (section == nullptr) {
      LIEF_ERR("Can't find a section associated with the address 0x{:x}", address);
      return;
    }

    span<uint8_t> content = section->writable_content();
    const uint64_t offset = address - section->file_offset();
    if (offset > content.size() || (offset + size) > content.size()) {
      LIEF_ERR("The patch value ({} bytes @0x{:x}) is out of bounds of the segment (limit: 0x{:x})",
               size, offset, content.size());
    }

    switch (size) {
      case sizeof(uint8_t):
        {
          auto X = static_cast<uint8_t>(patch_value);
          memcpy(content.data() + offset, &X, sizeof(uint8_t));
          break;
        }

      case sizeof(uint16_t):
        {
          auto X = static_cast<uint16_t>(patch_value);
          memcpy(content.data() + offset, &X, sizeof(uint16_t));
          break;
        }

      case sizeof(uint32_t):
        {
          auto X = static_cast<uint32_t>(patch_value);
          memcpy(content.data() + offset, &X, sizeof(uint32_t));
          break;
        }

      case sizeof(uint64_t):
        {
          auto X = static_cast<uint64_t>(patch_value);
          memcpy(content.data() + offset, &X, sizeof(uint64_t));
          break;
        }

      default:
        {
          LIEF_ERR("The provided size ({}) does not match the size of an integer", size);
          return;
        }
    }

    return;
  }


  Segment* segment_topatch = segment_from_virtual_address(address);
  if (segment_topatch == nullptr) {
    LIEF_ERR("Can't find a segment associated with the virtual address 0x{:x}", address);
    return;
  }

  const uint64_t offset = address - segment_topatch->virtual_address();
  span<uint8_t> content = segment_topatch->writable_content();
  if (offset > content.size() || (offset + size) > content.size()) {
    LIEF_ERR("The patch value ({} bytes @0x{:x}) is out of bounds of the segment (limit: 0x{:x})",
             size, offset, content.size());
  }
  switch (size) {
    case sizeof(uint8_t):
      {
        const auto X = static_cast<uint8_t>(patch_value);
        memcpy(content.data() + offset, &X, sizeof(uint8_t));
        break;
      }

    case sizeof(uint16_t):
      {
        const auto X = static_cast<uint16_t>(patch_value);
        memcpy(content.data() + offset, &X, sizeof(uint16_t));
        break;
      }

    case sizeof(uint32_t):
      {
        const auto X = static_cast<uint32_t>(patch_value);
        memcpy(content.data() + offset, &X, sizeof(uint32_t));
        break;
      }

    case sizeof(uint64_t):
      {
        const auto X = static_cast<uint64_t>(patch_value);
        memcpy(content.data() + offset, &X, sizeof(uint64_t));
        break;
      }

    default:
      {
        LIEF_ERR("The provided size ({}) does not match the size of an integer", size);
        return;
      }
  }
}


void Binary::patch_pltgot(const Symbol& symbol, uint64_t address) {
  it_pltgot_relocations pltgot_relocations = this->pltgot_relocations();
  const auto it_relocation = std::find_if(std::begin(pltgot_relocations), std::end(pltgot_relocations),
      [&symbol] (const Relocation& relocation) {
        return relocation.has_symbol() && relocation.symbol() == &symbol;
      });

  if (it_relocation == std::end(pltgot_relocations)) {
    LIEF_ERR("Unable to find the relocation associated with the symbol {}",
             symbol.name());
    return;
  }

  uint64_t got_address = (*it_relocation).address();
  patch_address(got_address, address, sizeof(uint64_t));
}

void Binary::patch_pltgot(const std::string& symbol_name, uint64_t address) {
  std::for_each(std::begin(dynamic_symbols_), std::end(dynamic_symbols_),
      [&symbol_name, address, this] (const std::unique_ptr<Symbol>& s) {
        if (s->name() == symbol_name) {
          patch_pltgot(*s, address);
        }
      });
}

const Segment* Binary::segment_from_virtual_address(uint64_t address) const {
  const auto it_segment = std::find_if(segments_.cbegin(), segments_.cend(),
      [address] (const std::unique_ptr<Segment>& segment) {
        return segment->virtual_address() <= address &&
               address < (segment->virtual_address() + segment->virtual_size());
      });

  if (it_segment == segments_.cend()) {
    return nullptr;
  }

  return it_segment->get();

}

Segment* Binary::segment_from_virtual_address(uint64_t address) {
  return const_cast<Segment*>(static_cast<const Binary*>(this)->segment_from_virtual_address(address));
}


const Segment* Binary::segment_from_offset(uint64_t offset) const {
  const auto it_segment = std::find_if(segments_.cbegin(), segments_.cend(),
      [&offset] (const std::unique_ptr<Segment>& segment) {
        return segment->file_offset() <= offset &&
               offset < (segment->file_offset() + segment->physical_size());
      });

  if (it_segment == segments_.cend()) {
    return nullptr;
  }

  return it_segment->get();
}

Segment* Binary::segment_from_offset(uint64_t offset) {
  return const_cast<Segment*>(static_cast<const Binary*>(this)->segment_from_offset(offset));
}

void Binary::remove_section(const std::string& name, bool clear) {
  Section* sec = get_section(name);
  if (sec == nullptr) {
    return;
  }
  remove(*sec, clear);
}

bool Binary::has_section(const std::string& name) const {
  return get_section(name) != nullptr;
}

bool Binary::has_section_with_offset(uint64_t offset) const {
  const auto it_section = std::find_if(sections_.cbegin(), sections_.cend(),
      [offset] (const std::unique_ptr<Section>& section) {
        return section->offset() <= offset &&
               offset < (section->offset() + section->size());
      });

  return it_section != sections_.cend();
}

bool Binary::has_section_with_va(uint64_t va) const {
  const auto it_section = std::find_if(sections_.cbegin(), sections_.cend(),
      [va] (const std::unique_ptr<Section>& section) {
        return section->virtual_address() != 0 &&
               section->virtual_address() <= va &&
               va < (section->virtual_address() + section->size());
      });
  return it_section != sections_.cend();
}

void Binary::strip() {
  static_symbols_.clear();
  Section* symtab = get(ELF_SECTION_TYPES::SHT_SYMTAB);
  if (symtab != nullptr) {
    remove(*symtab, /* clear */ true);
  }
}


Symbol& Binary::add_static_symbol(const Symbol& symbol) {
  static_symbols_.push_back(std::make_unique<Symbol>(symbol));
  return *static_symbols_.back();
}


Symbol& Binary::add_dynamic_symbol(const Symbol& symbol, const SymbolVersion* version) {
  auto sym = std::make_unique<Symbol>(symbol);
  std::unique_ptr<SymbolVersion> symver;
  if (version == nullptr) {
    symver = std::make_unique<SymbolVersion>(SymbolVersion::global());
  } else {
    symver = std::make_unique<SymbolVersion>(*version);
  }

  sym->symbol_version_ = symver.get();

  dynamic_symbols_.push_back(std::move(sym));
  symbol_version_table_.push_back(std::move(symver));
  return *dynamic_symbols_.back();
}

result<uint64_t> Binary::virtual_address_to_offset(uint64_t virtual_address) const {
  const auto it_segment = std::find_if(std::begin(segments_), std::end(segments_),
      [virtual_address] (const std::unique_ptr<Segment>& segment) {
        return segment->type() == SEGMENT_TYPES::PT_LOAD &&
               segment->virtual_address() <= virtual_address &&
               virtual_address < (segment->virtual_address() + segment->virtual_size());
      });

  if (it_segment == std::end(segments_)) {
    LIEF_DEBUG("Address: 0x{:x}", virtual_address);
    return make_error_code(lief_errors::conversion_error);
  }

  uint64_t base_address = (*it_segment)->virtual_address() - (*it_segment)->file_offset();
  uint64_t offset       = virtual_address - base_address;

  return offset;
}

result<uint64_t> Binary::offset_to_virtual_address(uint64_t offset, uint64_t slide) const {
  const auto it_segment = std::find_if(std::begin(segments_), std::end(segments_),
      [offset] (const std::unique_ptr<Segment>& segment) {
        return segment->type() == SEGMENT_TYPES::PT_LOAD &&
               segment->file_offset() <= offset &&
               offset < (segment->file_offset() + segment->physical_size());
      });

  if (it_segment == std::end(segments_)) {
    if (slide > 0) {
      return slide + offset;
    }
    return imagebase() + offset;
  }

  const uint64_t base_address = (*it_segment)->virtual_address() - (*it_segment)->file_offset();
  if (slide > 0) {
    return (base_address - imagebase()) + slide + offset;
  }
  return base_address + offset;
}


bool Binary::has_interpreter() const {
  const auto it_segment_interp = std::find_if(std::begin(segments_), std::end(segments_),
                                              [] (const std::unique_ptr<Segment>& segment) {
                                                return segment->type() == SEGMENT_TYPES::PT_INTERP;
                                              });
  return it_segment_interp != std::end(segments_) && !interpreter_.empty();
}

const std::string& Binary::interpreter() const {
  return interpreter_;
}

void Binary::interpreter(const std::string& interpreter) {
  interpreter_ = interpreter;
}


void Binary::write(const std::string& filename) {
  Builder builder{*this};
  builder.build();
  builder.write(filename);
}

void Binary::write(std::ostream& os) {
  Builder builder{*this};
  builder.build();
  builder.write(os);
}

uint64_t Binary::entrypoint() const {
  return header().entrypoint();
}


const Section* Binary::section_from_offset(uint64_t offset, bool skip_nobits) const {
  const auto it_section = std::find_if(sections_.cbegin(), sections_.cend(),
      [offset, skip_nobits] (const std::unique_ptr<Section>& section) {
        if (skip_nobits && section->type() == ELF_SECTION_TYPES::SHT_NOBITS) {
          return false;
        }
        return section->offset() <= offset &&
               offset < (section->offset() + section->size());
      });

  if (it_section == sections_.cend()) {
    return nullptr;
  }

  return it_section->get();
}

Section* Binary::section_from_offset(uint64_t offset, bool skip_nobits) {
  return const_cast<Section*>(static_cast<const Binary*>(this)->section_from_offset(offset, skip_nobits));
}


const Section* Binary::section_from_virtual_address(uint64_t address, bool skip_nobits) const {
  const auto it_section = std::find_if(sections_.cbegin(), sections_.cend(),
      [address, skip_nobits] (const std::unique_ptr<Section>& section) {
        if (skip_nobits && section->type() == ELF_SECTION_TYPES::SHT_NOBITS) {
          return false;
        }
        return section->virtual_address() != 0 &&
               section->virtual_address() <= address &&
               address < (section->virtual_address() + section->size());
      });

  if (it_section == sections_.cend()) {
    return nullptr;
  }

  return it_section->get();
}

Section* Binary::section_from_virtual_address(uint64_t address, bool skip_nobits) {
  return const_cast<Section*>(static_cast<const Binary*>(this)->section_from_virtual_address(address, skip_nobits));
}

std::vector<uint8_t> Binary::get_content_from_virtual_address(uint64_t virtual_address, uint64_t size, LIEF::Binary::VA_TYPES) const {
  const Segment* segment = segment_from_virtual_address(virtual_address);
  if (segment == nullptr) {
    return {};
  }

  span<const uint8_t> content = segment->content();
  const uint64_t offset = virtual_address - segment->virtual_address();
  uint64_t checked_size = size;
  if ((offset + checked_size) > content.size()) {
    checked_size = checked_size - (offset + checked_size - content.size());
  }

  return {content.data() + offset, content.data() + offset + checked_size};
}


const DynamicEntry* Binary::get(DYNAMIC_TAGS tag) const {
  const auto it_entry = std::find_if(std::begin(dynamic_entries_), std::end(dynamic_entries_),
                                     [tag] (const std::unique_ptr<DynamicEntry>& entry) {
                                       return entry->tag() == tag;
                                     });
  if (it_entry == std::end(dynamic_entries_)) {
    return nullptr;
  }
  return it_entry->get();
}

DynamicEntry* Binary::get(DYNAMIC_TAGS tag) {
  return const_cast<DynamicEntry*>(static_cast<const Binary*>(this)->get(tag));
}


bool Binary::has(DYNAMIC_TAGS tag) const {
  return get(tag) != nullptr;
}

const Segment* Binary::get(SEGMENT_TYPES type) const {
  const auto it_segment = std::find_if(std::begin(segments_), std::end(segments_),
                                       [type] (const std::unique_ptr<Segment>& segment) {
                                         return segment->type() == type;
                                       });
  if (it_segment == std::end(segments_)) {
    return nullptr;
  }

  return it_segment->get();
}


Segment* Binary::get(SEGMENT_TYPES type) {
  return const_cast<Segment*>(static_cast<const Binary*>(this)->get(type));
}

const Note* Binary::get(NOTE_TYPES type) const {
  const auto it_note = std::find_if(std::begin(notes_), std::end(notes_),
                              [type] (const std::unique_ptr<Note>& note) {
                                return static_cast<NOTE_TYPES>(note->type()) == type;
                              });
  if (it_note == std::end(notes_)) {
    return nullptr;
  }

  return it_note->get();
}


Note* Binary::get(NOTE_TYPES type) {
  return const_cast<Note*>(static_cast<const Binary*>(this)->get(type));
}

const Section* Binary::get(ELF_SECTION_TYPES type) const {
  const auto it_section = std::find_if(std::begin(sections_), std::end(sections_),
                                       [type] (const std::unique_ptr<Section>& section) {
                                         return section->type() == type;
                                       });
  if (it_section == std::end(sections_)) {
    return nullptr;
  }

  return it_section->get();
}


Section* Binary::get(ELF_SECTION_TYPES type) {
  return const_cast<Section*>(static_cast<const Binary*>(this)->get(type));
}


bool Binary::has(SEGMENT_TYPES type) const {
  return get(type) != nullptr;
}

bool Binary::has(NOTE_TYPES type) const {
  return get(type) != nullptr;
}

bool Binary::has(ELF_SECTION_TYPES type) const {
  return get(type) != nullptr;
}



void Binary::permute_dynamic_symbols(const std::vector<size_t>& permutation) {
  std::set<size_t> done;
  for (size_t i = 0; i < permutation.size(); ++i) {
    if (permutation[i] == i || done.count(permutation[i]) > 0) {
      continue;
    }

    if (dynamic_symbols_[i]->has_version() && dynamic_symbols_[permutation[i]]->has_version()) {
      std::swap(symbol_version_table_[i], symbol_version_table_[permutation[i]]);
      std::swap(dynamic_symbols_[i], dynamic_symbols_[permutation[i]]);
      done.insert(permutation[i]);
      done.insert(i);
    } else if (!dynamic_symbols_[i]->has_version() && !dynamic_symbols_[permutation[i]]->has_version()) {
      std::swap(dynamic_symbols_[i], dynamic_symbols_[permutation[i]]);
      done.insert(permutation[i]);
      done.insert(i);
    } else {
      LIEF_ERR("Can't apply permutation at index #{:d}", i);
    }

  }
}

LIEF::Header Binary::get_abstract_header() const {
  LIEF::Header header;
  const std::pair<ARCHITECTURES, std::set<MODES>>& am = this->header().abstract_architecture();
  header.architecture(am.first);
  header.modes(am.second);
  header.entrypoint(this->header().entrypoint());

  if (this->header().file_type() == E_TYPE::ET_DYN && has_interpreter()) { // PIE
    header.object_type(OBJECT_TYPES::TYPE_EXECUTABLE);
  } else {
    header.object_type(this->header().abstract_object_type());
  }

  header.endianness(this->header().abstract_endianness());

  return header;
}


bool Binary::has_notes() const {
  const auto it_segment_note = std::find_if(std::begin(segments_), std::end(segments_),
                                            [] (const std::unique_ptr<Segment>& segment) {
                                              return segment->type() == SEGMENT_TYPES::PT_NOTE;
                                            });

  return it_segment_note != std::end(segments_) && notes().size() > 0;
}

Binary::it_const_notes Binary::notes() const {
  return notes_;
}

Binary::it_notes Binary::notes() {
  return notes_;
}


void Binary::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool Binary::use_gnu_hash() const {
  return gnu_hash_ != nullptr && has(DYNAMIC_TAGS::DT_GNU_HASH);
}


const GnuHash* Binary::gnu_hash() const {
  if (!use_gnu_hash()) {
    return nullptr;
  }
  return gnu_hash_.get();
}


bool Binary::use_sysv_hash() const {
  return sysv_hash_ != nullptr && has(DYNAMIC_TAGS::DT_HASH);
}

const SysvHash* Binary::sysv_hash() const {
  if (!use_sysv_hash()) {
    return nullptr;
  }
  return sysv_hash_.get();
}


void Binary::shift_sections(uint64_t from, uint64_t shift) {
  LIEF_DEBUG("[+] Shift Sections");
  for (std::unique_ptr<Section>& section : sections_) {
    if (section->is_frame()) {
      continue;
    }
    if (section->file_offset() >= from) {
      LIEF_DEBUG("[BEFORE] {}", *section);
      section->file_offset(section->file_offset() + shift);
      if (section->virtual_address() > 0) {
        section->virtual_address(section->virtual_address() + shift);
      }
      LIEF_DEBUG("[AFTER ] {}", *section);
    }
  }
}

void Binary::shift_segments(uint64_t from, uint64_t shift) {

  LIEF_DEBUG("Shift segments by 0x{:x} from 0x{:x}", shift, from);

  for (std::unique_ptr<Segment>& segment : segments_) {
    if (segment->file_offset() >= from) {
      LIEF_DEBUG("[BEFORE] {}", *segment);
      segment->file_offset(segment->file_offset() + shift);
      segment->virtual_address(segment->virtual_address() + shift);
      segment->physical_address(segment->physical_address() + shift);
      LIEF_DEBUG("[AFTER ] {}", *segment);
    }
  }
}

void Binary::shift_dynamic_entries(uint64_t from, uint64_t shift) {
  LIEF_DEBUG("Shift dynamic entries by 0x{:x} from 0x{:x}", shift, from);

  for (std::unique_ptr<DynamicEntry>& entry : dynamic_entries_) {
    LIEF_DEBUG("[BEFORE] {}", *entry);
    switch (entry->tag()) {
      case DYNAMIC_TAGS::DT_PLTGOT:
      case DYNAMIC_TAGS::DT_HASH:
      case DYNAMIC_TAGS::DT_GNU_HASH:
      case DYNAMIC_TAGS::DT_STRTAB:
      case DYNAMIC_TAGS::DT_SYMTAB:
      case DYNAMIC_TAGS::DT_RELA:
      case DYNAMIC_TAGS::DT_REL:
      case DYNAMIC_TAGS::DT_JMPREL:
      case DYNAMIC_TAGS::DT_INIT:
      case DYNAMIC_TAGS::DT_FINI:
      case DYNAMIC_TAGS::DT_VERSYM:
      case DYNAMIC_TAGS::DT_VERDEF:
      case DYNAMIC_TAGS::DT_VERNEED:
        {

          if (entry->value() >= from) {
            entry->value(entry->value() + shift);
          }
          break;
        }

      case DYNAMIC_TAGS::DT_INIT_ARRAY:
      case DYNAMIC_TAGS::DT_FINI_ARRAY:
      case DYNAMIC_TAGS::DT_PREINIT_ARRAY:
        {
          DynamicEntryArray::array_t& array = entry->as<DynamicEntryArray>()->array();
          for (uint64_t& address : array) {
            if (address >= from) {
              if ((type() == ELF_CLASS::ELFCLASS32 && static_cast<int32_t>(address) > 0) ||
                  (type() == ELF_CLASS::ELFCLASS64 && static_cast<int64_t>(address) > 0))
              {
                address += shift;
              }
            }
          }

          if (entry->value() >= from) {
            entry->value(entry->value() + shift);
          }
          break;
        }

      default:
        {
          //LIEF_DEBUG("{} not supported", to_string(entry->tag()));
        }
    }
    LIEF_DEBUG("[AFTER ] {}", *entry);
  }
}


void Binary::shift_symbols(uint64_t from, uint64_t shift) {
  LIEF_DEBUG("Shift symbols by 0x{:x} from 0x{:x}", shift, from);
  for (Symbol& symbol : symbols()) {
    if (symbol.value() >= from) {
      LIEF_DEBUG("[BEFORE] {}", symbol);
      symbol.value(symbol.value() + shift);
      LIEF_DEBUG("[AFTER ] {}", symbol);
    }
  }
}


void Binary::shift_relocations(uint64_t from, uint64_t shift) {
  const ARCH arch = header().machine_type();
  LIEF_DEBUG("Shift relocations for {} by 0x{:x} from 0x{:x}", to_string(arch), shift, from);

  switch(arch) {
    case ARCH::EM_ARM:
      {
        patch_relocations<ARCH::EM_ARM>(from, shift);
        break;
      }

    case ARCH::EM_AARCH64:
      {
        patch_relocations<ARCH::EM_AARCH64>(from, shift);
        break;
      }

    case ARCH::EM_X86_64:
      {
        patch_relocations<ARCH::EM_X86_64>(from, shift);
        break;
      }

    case ARCH::EM_386:
      {
        patch_relocations<ARCH::EM_386>(from, shift);
        break;
      }

    case ARCH::EM_PPC:
      {
        patch_relocations<ARCH::EM_PPC>(from, shift);
        break;
      }

      /*
    case ARCH::EM_PPC64:
      {
        patch_relocations<ARCH::EM_PPC64>(from, shift);
        break;
      }

      case ARCH::EM_RISCV:
        {
          patch_relocations<ARCH::EM_RISCV>(from, shift);
          break;
        }
      */

    default:
      {
        LIEF_DEBUG("Relocations for architecture {} is not handled", to_string(arch));
      }
  }
}


uint64_t Binary::last_offset_section() const {
  return std::accumulate(std::begin(sections_), std::end(sections_), 0llu,
      [] (uint64_t offset, const std::unique_ptr<Section>& section) {
        if (section->is_frame()) {
          return offset;
        }
        return std::max<uint64_t>(section->file_offset() + section->size(), offset);
      });
}


uint64_t Binary::last_offset_segment() const {
  return std::accumulate(std::begin(segments_), std::end(segments_), 0llu,
      [] (uint64_t offset, const std::unique_ptr<Segment>& segment) {
        return std::max<uint64_t>(segment->file_offset() + segment->physical_size(), offset);
      });
}


uint64_t Binary::next_virtual_address() const {

  uint64_t va = std::accumulate(std::begin(segments_), std::end(segments_), uint64_t{ 0u },
            [] (uint64_t address, const std::unique_ptr<Segment>& segment) {
              return std::max<uint64_t>(segment->virtual_address() + segment->virtual_size(), address);
            });

  if (type() == ELF_CLASS::ELFCLASS32) {
    va = round<uint32_t>(static_cast<uint32_t>(va));
  }

  if (type() == ELF_CLASS::ELFCLASS64) {
    va = round<uint64_t>(static_cast<uint64_t>(va));
  }

  return va;
}


DynamicEntryLibrary& Binary::add_library(const std::string& library_name) {
  return *add(DynamicEntryLibrary{library_name}).as<DynamicEntryLibrary>();
}


void Binary::remove_library(const std::string& library_name) {
  DynamicEntryLibrary* lib = get_library(library_name);
  if (lib == nullptr) {
    LIEF_ERR("Can't find a library with the name '{}'", library_name);
    return;
  }
  remove(*lib);
}


DynamicEntryLibrary* Binary::get_library(const std::string& library_name) {
  return const_cast<DynamicEntryLibrary*>(static_cast<const Binary*>(this)->get_library(library_name));
}

const DynamicEntryLibrary* Binary::get_library(const std::string& library_name) const {
  const auto it_needed = std::find_if(std::begin(dynamic_entries_), std::end(dynamic_entries_),
      [&library_name] (const std::unique_ptr<DynamicEntry>& entry) {
        return DynamicEntryLibrary::classof(entry.get()) &&
               entry->as<const DynamicEntryLibrary>()->name() == library_name;
      });
  if (it_needed == std::end(dynamic_entries_)) {
    return nullptr;
  }
  return static_cast<const DynamicEntryLibrary*>(it_needed->get());
}

bool Binary::has_library(const std::string& name) const {
  return get_library(name) != nullptr;
}


LIEF::Binary::functions_t Binary::tor_functions(DYNAMIC_TAGS tag) const {
  LIEF::Binary::functions_t functions;
  const DynamicEntry* entry = get(tag);
  if (entry == nullptr || !DynamicEntryArray::classof(entry)) {
    return {};
  }
  const DynamicEntryArray::array_t& array = entry->as<DynamicEntryArray>()->array();
  functions.reserve(array.size());

  for (uint64_t x : array) {
    if (x != 0 &&
        static_cast<uint32_t>(x) != static_cast<uint32_t>(-1) &&
        x != static_cast<uint64_t>(-1))
    {
      functions.emplace_back(x);
    }
  }
  return functions;
}

// Ctor
LIEF::Binary::functions_t Binary::ctor_functions() const {
  LIEF::Binary::functions_t functions;

  LIEF::Binary::functions_t init = tor_functions(DYNAMIC_TAGS::DT_INIT_ARRAY);
  std::transform(
      std::make_move_iterator(std::begin(init)), std::make_move_iterator(std::end(init)),
      std::back_inserter(functions),
      [] (Function&& f) {
        f.add(Function::FLAGS::CONSTRUCTOR);
        f.name("__dt_init_array");
        return f;
      });

  LIEF::Binary::functions_t preinit = tor_functions(DYNAMIC_TAGS::DT_PREINIT_ARRAY);
  std::transform(
      std::make_move_iterator(std::begin(preinit)),
      std::make_move_iterator(std::end(preinit)),
      std::back_inserter(functions),
      [] (Function&& f) {
        f.add(Function::FLAGS::CONSTRUCTOR);
        f.name("__dt_preinit_array");
        return f;
      });

  const DynamicEntry* dt_init = get(DYNAMIC_TAGS::DT_INIT);
  if (dt_init != nullptr) {
    functions.emplace_back("__dt_init",
          dt_init->value(), Function::flags_list_t{Function::FLAGS::CONSTRUCTOR});
  }
  return functions;
}


LIEF::Binary::functions_t Binary::dtor_functions() const {

  LIEF::Binary::functions_t functions;

  LIEF::Binary::functions_t fini = tor_functions(DYNAMIC_TAGS::DT_FINI_ARRAY);
  std::transform(
      std::make_move_iterator(std::begin(fini)), std::make_move_iterator(std::end(fini)),
      std::back_inserter(functions),
      [] (Function&& f) {
        f.add(Function::FLAGS::DESTRUCTOR);
        f.name("__dt_fini_array");
        return f;
      });

  const DynamicEntry* dt_fini = get(DYNAMIC_TAGS::DT_FINI);
  if (dt_fini != nullptr) {
    functions.emplace_back("__dt_fini",
        dt_fini->value(), Function::flags_list_t{Function::FLAGS::DESTRUCTOR});
  }
  return functions;
}


const Relocation* Binary::get_relocation(uint64_t address) const {
  const auto it = std::find_if(std::begin(relocations_), std::end(relocations_),
                               [address] (const std::unique_ptr<Relocation>& r) {
                                 return r->address() == address;
                               });

  if (it != std::end(relocations_)) {
    return it->get();
  }

  return nullptr;

}

Relocation* Binary::get_relocation(uint64_t address) {
  return const_cast<Relocation*>(static_cast<const Binary*>(this)->get_relocation(address));
}

const Relocation* Binary::get_relocation(const Symbol& symbol) const {
  const auto it = std::find_if(std::begin(relocations_), std::end(relocations_),
                               [&symbol] (const std::unique_ptr<Relocation>& r) {
                                 return r->has_symbol() && r->symbol() == &symbol;
                               });

  if (it != std::end(relocations_)) {
    return it->get();
  }

  return nullptr;
}

Relocation* Binary::get_relocation(const Symbol& symbol) {
  return const_cast<Relocation*>(static_cast<const Binary*>(this)->get_relocation(symbol));
}

const Relocation* Binary::get_relocation(const std::string& symbol_name) const {
  const LIEF::Symbol* sym = get_symbol(symbol_name);
  if (sym == nullptr) {
    return nullptr;
  }
  return get_relocation(*sym->as<Symbol>());
}

Relocation* Binary::get_relocation(const std::string& symbol_name) {
  return const_cast<Relocation*>(static_cast<const Binary*>(this)->get_relocation(symbol_name));
}


LIEF::Binary::functions_t Binary::armexid_functions() const {
  LIEF::Binary::functions_t funcs;

  static const auto expand_prel31 = [] (uint32_t word, uint32_t base) {
    uint32_t offset = word & 0x7fffffff;
    if ((offset & 0x40000000) != 0u) {
      offset |= ~static_cast<uint32_t>(0x7fffffff);
    }
    return base + offset;
  };

  const Segment* exidx = get(SEGMENT_TYPES::PT_ARM_EXIDX);
  if (exidx != nullptr) {
    span<const uint8_t> content = exidx->content();
    const size_t nb_functions = content.size() / (2 * sizeof(uint32_t));
    funcs.reserve(nb_functions);

    const auto* entries = reinterpret_cast<const uint32_t*>(content.data());
    for (size_t i = 0; i < 2 * nb_functions; i += 2) {
      uint32_t first_word  = entries[i];
      /*uint32_t second_word = entries[i + 1]; */

      if ((first_word & 0x80000000) == 0) {
        uint32_t prs_data = expand_prel31(first_word, exidx->virtual_address() + i * sizeof(uint32_t));
        funcs.emplace_back(prs_data);
      }
    }
  }
  return funcs;
}


LIEF::Binary::functions_t Binary::eh_frame_functions() const {
  LIEF::Binary::functions_t functions;
  const Segment* eh_frame_seg = get(SEGMENT_TYPES::PT_GNU_EH_FRAME);
  if (eh_frame_seg == nullptr) {
    return functions;
  }

  const uint64_t eh_frame_addr = eh_frame_seg->virtual_address();
  const uint64_t eh_frame_rva  = eh_frame_addr - imagebase();
  uint64_t eh_frame_off  = 0;

  if (auto res = virtual_address_to_offset(eh_frame_addr)) {
    eh_frame_off = *res;
  } else {
    LIEF_WARN("Can't convert the PT_GNU_EH_FRAME virtual address into an offset (0x{:x})", eh_frame_addr);
    return functions;
  }

  const auto it_load_segment = std::find_if(std::begin(segments_), std::end(segments_),
      [eh_frame_addr] (const std::unique_ptr<Segment>& s) {
        return s->type() == SEGMENT_TYPES::PT_LOAD &&
               s->virtual_address() <= eh_frame_addr &&
               eh_frame_addr < (s->virtual_address() + s->virtual_size());
      });

  if (it_load_segment == std::end(segments_)) {
    LIEF_ERR("Unable to find the LOAD segment associated with PT_GNU_EH_FRAME");
    return functions;
  }
  const std::unique_ptr<Segment>& load_segment = *it_load_segment;

  const bool is64 = (type() == ELF_CLASS::ELFCLASS64);
  eh_frame_off = eh_frame_off - load_segment->file_offset();

  SpanStream vs = load_segment->content();
  vs.setpos(eh_frame_off);

  if (vs.size() < 4 * sizeof(uint8_t)) {
    LIEF_WARN("Unable to read EH frame header");
    return functions;
  }

  // Read Eh Frame header
  auto version          = *vs.read<uint8_t>();
  auto eh_frame_ptr_enc = *vs.read<uint8_t>(); // How pointers are encoded
  auto fde_count_enc    = *vs.read<uint8_t>();
  auto table_enc        = *vs.read<uint8_t>();

  auto res_eh_frame_ptr = vs.read_dwarf_encoded(eh_frame_ptr_enc);
  if (!res_eh_frame_ptr) {
    LIEF_ERR("Can't decode eh_frame_ptr_enc");
    return functions;
  }
  auto eh_frame_ptr = *res_eh_frame_ptr;
  int64_t fde_count    = -1;

  if (static_cast<DWARF::EH_ENCODING>(fde_count_enc) != DWARF::EH_ENCODING::OMIT) {
    auto res_count = vs.read_dwarf_encoded(fde_count_enc);
    if (!res_count) {
      return functions;
    }
    fde_count = *res_count;
  }

  if (version != 1) {
    LIEF_WARN("EH Frame header version is not 1 ({:d}) structure may have been corrupted!", version);
  }

  if (fde_count < 0) {
    LIEF_WARN("fde_count is corrupted (negative value)");
    fde_count = 0;
  }


  LIEF_DEBUG("  eh_frame_ptr_enc: 0x{:x}", static_cast<uint32_t>(eh_frame_ptr_enc));
  LIEF_DEBUG("  fde_count_enc:    0x{:x}", static_cast<uint32_t>(fde_count_enc));
  LIEF_DEBUG("  table_enc:        0x{:x}", static_cast<uint32_t>(table_enc));
  LIEF_DEBUG("  eh_frame_ptr:     0x{:x}", static_cast<uint32_t>(eh_frame_ptr));
  LIEF_DEBUG("  fde_count:        0x{:x}", static_cast<uint32_t>(fde_count));

  auto table_bias = static_cast<DWARF::EH_ENCODING>(table_enc & 0xF0);

  for (size_t i = 0; i < static_cast<size_t>(fde_count); ++i) {

    // Read Function address / FDE address within the
    // Binary search table
    auto res_init_loc = vs.read_dwarf_encoded(table_enc);
    if (!res_init_loc) {
      LIEF_ERR("Can't read Dwarf initial_location");
      return functions;
    }
    uint32_t initial_location = *res_init_loc;
    auto res_address = vs.read_dwarf_encoded(table_enc);
    if (!res_address) {
      LIEF_ERR("Can't read Dwarf address");
      return functions;
    }
    uint32_t address = *res_address;
    uint64_t bias    = 0;

    switch (table_bias) {
      case DWARF::EH_ENCODING::PCREL:
        {
          bias = (eh_frame_rva + vs.pos());
          break;
        }

      case DWARF::EH_ENCODING::TEXTREL:
        {
          LIEF_WARN("EH_ENCODING::TEXTREL is not supported");
          break;
        }

      case DWARF::EH_ENCODING::DATAREL:
        {
          bias = eh_frame_rva;
          break;
        }

      case DWARF::EH_ENCODING::FUNCREL:
        {
          LIEF_WARN("EH_ENCODING::FUNCREL is not supported");
          break;
        }

      case DWARF::EH_ENCODING::ALIGNED:
        {
          LIEF_WARN("EH_ENCODING::ALIGNED is not supported");
          break;
        }

      default:
        {
          LIEF_WARN("Encoding not supported!");
          break;
        }
    }
    initial_location += bias;
    address          += bias;

    LIEF_DEBUG("Initial location: 0x{:x}", initial_location);
    LIEF_DEBUG("Address: 0x{:x}", address);
    LIEF_DEBUG("Bias: 0x{:x}", bias);
    const size_t saved_pos = vs.pos();
    LIEF_DEBUG("Go to eh_frame_off + address - bias: 0x{:x}", eh_frame_off + address - bias);
    // Go to the FDE structure
    vs.setpos(eh_frame_off + address - bias);
    {
      // Beginning of the FDE structure (to continue)
      auto res_fde_length = vs.read<uint32_t>();
      if (!res_fde_length) {
        LIEF_ERR("Can't read FDE length");
        vs.setpos(saved_pos);
        continue;
      }
      uint64_t fde_length = *res_fde_length;
      if (fde_length == static_cast<uint32_t>(-1)) {
        if (vs.can_read<uint64_t>()) {
          fde_length = *vs.read<uint64_t>();
        }
      }
      auto cie_pointer = vs.read<uint32_t>();
      if (!cie_pointer) {
        LIEF_ERR("Can't read cie pointer");
        vs.setpos(saved_pos);
        continue;
      }

      if (*cie_pointer == 0) {
        LIEF_DEBUG("cie_pointer is null!");
        vs.setpos(saved_pos);
        continue;
      }

      const uint32_t cie_offset = vs.pos() - *cie_pointer - sizeof(uint32_t);

      LIEF_DEBUG("fde_length@0x{:x}: 0x{:x}", address - bias, fde_length);
      LIEF_DEBUG("cie_pointer 0x{:x}", *cie_pointer);
      LIEF_DEBUG("cie_offset 0x{:x}", cie_offset);


      // Go to CIE structure
      //uint8_t augmentation_data = static_cast<uint8_t>(DWARF::EH_ENCODING::OMIT);

      const size_t saved_pos = vs.pos();
      uint8_t augmentation_data = 0;
      vs.setpos(cie_offset);
      {
        auto res_cie_length = vs.read<uint32_t>();
        if (!res_cie_length) {
          LIEF_ERR("Can't read cie_length");
          return functions;
        }
        uint64_t cie_length = *res_cie_length;

        if (cie_length == static_cast<uint32_t>(-1)) {
          if (vs.can_read<uint64_t>()) {
            cie_length = *vs.read<uint64_t>();
          }
        }

        auto cie_id = vs.read<uint32_t>();
        if (!cie_id) {
          LIEF_ERR("Can't read cie_id");
          return functions;
        }

        auto version = vs.read<uint8_t>();
        if (!version) {
          LIEF_ERR("Can't read version");
          return functions;
        }

        if (*cie_id != 0) {
          LIEF_WARN("CIE ID is not 0 ({:d})", *cie_id);
        }

        if (*version != 1) {
          LIEF_WARN("CIE ID is not 1 ({:d})", *version);
        }

        LIEF_DEBUG("cie_length: 0x{:x}", cie_length);
        LIEF_DEBUG("ID: {:d}", *cie_id);
        LIEF_DEBUG("Version: {:d}", *version);

        auto res_cie_augmentation_string = vs.read_string();
        if (!res_cie_augmentation_string) {
          LIEF_ERR("Can't read cie_augmentation_string");
          return functions;
        }
        std::string cie_augmentation_string = std::move(*res_cie_augmentation_string);

        LIEF_DEBUG("CIE Augmentation {}", cie_augmentation_string);
        if (cie_augmentation_string.find("eh") != std::string::npos) {
          if (is64) {
            /* uint64_t eh_data = */ vs.read<uint64_t>();
          } else {
            /* uint32_t eh_data = */ vs.read<uint32_t>();
          }
        }

        /* uint64_t code_alignment         = */ vs.read_uleb128();
        /* int64_t  data_alignment         = */ vs.read_sleb128();
        /* uint64_t return_addres_register = */ vs.read_uleb128();
        if (cie_augmentation_string.find('z') != std::string::npos) {
          /* int64_t  augmentation_length    = */ vs.read_uleb128();
        }
        LIEF_DEBUG("cie_augmentation_string: {}", cie_augmentation_string);


        if (!cie_augmentation_string.empty() && cie_augmentation_string[0] == 'z') {
          if (cie_augmentation_string.find('R') != std::string::npos) {
            auto aug_data = vs.read<uint8_t>();
            if (!aug_data) {
              LIEF_ERR("Can't read augmentation data");
              return functions;
            }
            augmentation_data = *aug_data;
          } else {
            LIEF_WARN("Augmentation string '{}' is not supported", cie_augmentation_string);
          }
        }
      }
      LIEF_DEBUG("Augmentation data 0x{:x}", static_cast<uint32_t>(augmentation_data));

      // Go back to FDE Structure
      vs.setpos(saved_pos);
      auto res = vs.read_dwarf_encoded(augmentation_data);
      if (!res) {
        LIEF_ERR("Can't read Dwarf encoded function begin");
        return functions;
      }
      int32_t function_begin = eh_frame_rva + vs.pos() + *res;
      res = vs.read_dwarf_encoded(augmentation_data);
      if (!res) {
        LIEF_ERR("Can't read dward encoded size");
        return functions;
      }
      int32_t size = *res;

      // Create the function
      Function f{static_cast<uint64_t>(initial_location + imagebase())};
      f.size(size);
      functions.push_back(std::move(f));
      LIEF_DEBUG("PC@0x{:x}:0x{:x}", function_begin, size);
    }
    vs.setpos(saved_pos);
  }

  return functions;
}


LIEF::Binary::functions_t Binary::functions() const {

  static const auto func_cmd = [] (const Function& lhs, const Function& rhs) {
    return lhs.address() < rhs.address();
  };
  std::set<Function, decltype(func_cmd)> functions_set(func_cmd);

  LIEF::Binary::functions_t eh_frame_functions = this->eh_frame_functions();
  LIEF::Binary::functions_t armexid_functions  = this->armexid_functions();
  LIEF::Binary::functions_t ctors              = ctor_functions();
  LIEF::Binary::functions_t dtors              = dtor_functions();

  for (const Symbol& s : symbols()) {
    if (s.type() == ELF_SYMBOL_TYPES::STT_FUNC && s.value() > 0) {
      Function f{s.name(), s.value()};
      f.size(s.size());
      functions_set.insert(f);
    }
  }

  std::move(std::begin(ctors), std::end(ctors),
            std::inserter(functions_set, std::end(functions_set)));

  std::move(std::begin(dtors), std::end(dtors),
            std::inserter(functions_set, std::end(functions_set)));

  std::move(std::begin(eh_frame_functions), std::end(eh_frame_functions),
            std::inserter(functions_set, std::end(functions_set)));

  std::move(std::begin(armexid_functions), std::end(armexid_functions),
            std::inserter(functions_set, std::end(functions_set)));

  return {std::begin(functions_set), std::end(functions_set)};
}


uint64_t Binary::eof_offset() const {
  uint64_t last_offset_sections = 0;

  for (const std::unique_ptr<Section>& section : sections_) {
    if (section->type() != LIEF::ELF::ELF_SECTION_TYPES::SHT_NOBITS && !section->is_frame()) {
      last_offset_sections = std::max<uint64_t>(section->file_offset() + section->size(), last_offset_sections);
    }
  }

  const uint64_t section_header_size = type() == ELF_CLASS::ELFCLASS64 ?
                                                 sizeof(typename details::ELF64::Elf_Shdr) :
                                                 sizeof(typename details::ELF32::Elf_Shdr);

  const uint64_t segment_header_size = type() == ELF_CLASS::ELFCLASS64 ?
                                                 sizeof(typename details::ELF64::Elf_Phdr) :
                                                 sizeof(typename details::ELF32::Elf_Phdr);

  const uint64_t end_sht_table =
      header().section_headers_offset() +
      sections_.size() * section_header_size;

  const uint64_t end_phdr_table =
      header().program_headers_offset() +
      segments_.size() * segment_header_size;

  last_offset_sections = std::max<uint64_t>({last_offset_sections, end_sht_table, end_phdr_table});

  const uint64_t last_offset_segments = last_offset_segment();
  const uint64_t last_offset          = std::max<uint64_t>(last_offset_sections, last_offset_segments);

  return last_offset;
}


bool Binary::has_overlay() const {
  return !overlay_.empty();
}

const Binary::overlay_t& Binary::overlay() const {
  return overlay_;
}

void Binary::overlay(Binary::overlay_t overlay) {
  overlay_ = std::move(overlay);
}


std::string Binary::shstrtab_name() const {
  const Header& hdr = header();
  const size_t shstrtab_idx = hdr.section_name_table_idx();
  if (shstrtab_idx < sections_.size()) {
    return sections_[shstrtab_idx]->name();
  }
  return ".shstrtab";
}

uint64_t Binary::relocate_phdr_table() {
  uint64_t offset = 0;
  if (header_.file_type() == E_TYPE::ET_DYN) {
    offset = relocate_phdr_table_pie();
    if (offset == 0) {
      LIEF_ERR("Can't relocated phdr table for this PIE binary");
    } else {
      return offset;
    }
  }

  LIEF_DEBUG("Try v1 relocator");
  if ((offset = relocate_phdr_table_v1()) == 0) {
    LIEF_DEBUG("Try v2 relocator");
    if ((offset = relocate_phdr_table_v2()) == 0) {
      LIEF_ERR("Can't relocate the phdr table for this binary. Please consider to open an issue");
      return 0;
    }
  }
  return offset;
}


uint64_t Binary::relocate_phdr_table_pie() {

  if (phdr_reloc_info_.new_offset > 0) {
    // Already relocated
    return phdr_reloc_info_.new_offset;
  }


  // --------------------------------------
  // Part 1: Make spaces for a new PHDR
  // --------------------------------------
  const uint64_t phdr_offset = header().program_headers_offset();
  uint64_t phdr_size         = 0;

  if (type() == ELF_CLASS::ELFCLASS32) {
    phdr_size = sizeof(details::ELF32::Elf_Phdr);
  }

  if (type() == ELF_CLASS::ELFCLASS64) {
    phdr_size = sizeof(details::ELF64::Elf_Phdr);
  }


  const uint64_t from = phdr_offset + phdr_size * segments_.size();

  /*
   * We could use a smaller shift value but 0x1000 eases the
   * support of corner cases like ADRP on AArch64.
   *
   * Note: 0x1000 enables to add up to 73 segments which should be enough
   *       in most of the cases
   *
   * e.g:
   * const ARCH arch = header_.machine_type();
   * uint64_t shift = align(phdr_size, 0x10);
   * if (arch == ARCH::EM_AARCH64 || arch == ARCH::EM_ARM) {
   *   shift = 0x1000;
   *   phdr_reloc_info_.new_offset = phdr_offset;
   *   phdr_reloc_info_.nb_segments = shift / phdr_size - header_.numberof_segments();
   * }
   */
  static constexpr size_t shift = 0x1000;

  phdr_reloc_info_.new_offset  = from;
  phdr_reloc_info_.nb_segments = shift / phdr_size - header_.numberof_segments();

  auto alloc = datahandler_->make_hole(from, shift);
  if (!alloc) {
    LIEF_ERR("Allocation failed");
    return 0;
  }

  LIEF_DEBUG("Header shift: 0x{:x}", shift);

  header().section_headers_offset(header().section_headers_offset() + shift);

  shift_sections(from, shift);
  shift_segments(from, shift);

  // Patch segment size for the segment which contains the new segment
  for (std::unique_ptr<Segment>& segment : segments_) {
    if (segment->file_offset() <= from &&
        from <= (segment->file_offset() + segment->physical_size()))
    {
      segment->virtual_size(segment->virtual_size()   + shift);
      segment->physical_size(segment->physical_size() + shift);
    }
  }

  shift_dynamic_entries(from, shift);
  shift_symbols(from, shift);
  shift_relocations(from, shift);

  if (type() == ELF_CLASS::ELFCLASS32) {
    fix_got_entries<details::ELF32>(from, shift);
  } else {
    fix_got_entries<details::ELF64>(from, shift);
  }

  if (header().entrypoint() >= from) {
    header().entrypoint(header().entrypoint() + shift);
  }
  return phdr_offset;
}

/*
 * This function relocates the phdr table in the case
 * where:
 *  1. The binary is NOT pie
 *  2. There is no gap between two adjacent segments (cf. relocate_phdr_table_v1)
 *
 * It performs the following modifications:
 *  1. Expand the bss section such as virtual size == file size
 *  2. Relocate the phdr table right after the (expanded) bss section
 *  3. Add a LOAD segment to wrap the new phdr location
 *
 */
uint64_t Binary::relocate_phdr_table_v2() {
  static constexpr size_t USER_SEGMENTS = 10; // We reserve space for 10 user's segments


  if (phdr_reloc_info_.new_offset > 0) {
    return phdr_reloc_info_.new_offset;
  }

  Header& header = this->header();

  const uint64_t phdr_size = type() == ELF_CLASS::ELFCLASS32 ?
                                       sizeof(details::ELF32::Elf_Phdr) :
                                       sizeof(details::ELF64::Elf_Phdr);


  std::vector<Segment*> load_seg;
  Segment* bss_segment = nullptr;
  size_t bss_cnt = 0;
  for (std::unique_ptr<Segment>& segment : segments_) {
    if (segment->type() == SEGMENT_TYPES::PT_LOAD) {
      load_seg.push_back(segment.get());
      if (segment->physical_size() < segment->virtual_size()) {
        bss_segment = segment.get();
        ++bss_cnt;
      }
    }
  }

  if (bss_cnt != 1 || bss_segment == nullptr) {
    LIEF_ERR("Zero or more than 1 bss-like segment!");
    return 0;
  }

  // "expand" the .bss area. It is required since the bss area that is mapped
  // needs to be set to 0
  const uint64_t original_psize = bss_segment->physical_size();

  /*
   * To compute the location of the new segments table,
   * we have to deal with some constraints:
   * 1. The new location virtual address (VA) must follow:
   *    VA = image_base + offset (1)
   * 2. The .bss area, which does not have a physical
   *    representation in the file, must be 0. Therefore,
   *    we can't use this space to put our new segment table.
   *    Consequently, we need to expand it in the file. (2)
   * 3. The req 2. is not enough and need to verify that the virtual address
   *    is suitable.
   *
   * Let's consider this layout:
   *  LOAD_1 0x000000 0x0000000000400000 0x000be4 0x000be4
   *  LOAD_2 0x000e00 0x0000000000401e00 0x000230 0x000238
   * We have to relocate the PHDR at the end of the file.
   * Because of Req[2.], we have to expand the last LOAD bss-like segment:
   *  LOAD_2.file_size = LOAD_2.virtual_size = 0x000230
   * So our new segment table **could** be located at:
   *  LOAD_2.file_offset + LOAD_2.file_size == 0x1030
   * Because of Req[1.] it would set the virtual address:
   *  Imagebase[0x400000] + 0x1030 = 0x401030
   * BUT if the size of the new segment table is too large,
   * it could override the next virtual address which is associated with LOAD_2.
   *  LOAD_NEW.VA = 0x401030 < LOAD_2.VA = 0x401e00
   *  Moreover, it might raise page alignment issues.
   *
   * Therefore, we **can't take** 0x1030 as offset for the new
   * segment table.
   * To avoid virtual overlap while still keeping Req[1.],
   * we need to use: LOAD_2.virtual_address - Imagebase[0x400000] + LOAD_2.virtual_size
   *                 \                                         /
   *                  ------------ Offset --------------------/
   * which should be aligned on a page size to avoid error.
   *
   * The issue https://github.com/lief-project/LIEF/issues/671
   * is a good example of what could go wrong.
   *
   * |WARNING|
   *  This modification can increase the binary size drastically
   *  if it contains a large BSS section.
   *
   * (1) This is enforced by the Linux loader which uses
   *     this relationship to compute the module base address
   * (2) man elf:
   *     .bss This section holds uninitialized data that contributes to
   *          the program's memory image. By definition, the system
   *          initializes the data with zeros when the program begins to
   *          run.  This section is of type SHT_NOBITS. The attribute
   *          types are SHF_ALLOC and SHF_WRITE.
   */
  const uint64_t new_phdr_offset = align(bss_segment->virtual_address() - imagebase()
                                         + bss_segment->virtual_size(), 0x1000);

  const size_t nb_segments = header.numberof_segments() +
                             /* custom PT_LOAD */ 1 + USER_SEGMENTS;

  const uint64_t new_phdr_size = nb_segments * phdr_size;
  phdr_reloc_info_.new_offset = new_phdr_offset;
  header.program_headers_offset(new_phdr_offset);

  size_t delta_pa = (bss_segment->virtual_size() - bss_segment->physical_size());

  phdr_reloc_info_.nb_segments = USER_SEGMENTS;
  auto alloc = datahandler_->make_hole(bss_segment->file_offset() + bss_segment->physical_size(), delta_pa);
  if (!alloc) {
    LIEF_ERR("Allocation failed");
    return 0;
  }
  bss_segment->physical_size(bss_segment->virtual_size());

  // Create a LOAD segment that wraps the new location of the PT_PHDR.
  auto new_segment_ptr = std::make_unique<Segment>();
  Segment* nsegment_addr = new_segment_ptr.get();
  nsegment_addr->type(SEGMENT_TYPES::PT_LOAD);
  nsegment_addr->virtual_size(new_phdr_size);
  nsegment_addr->physical_size(new_phdr_size);
  nsegment_addr->virtual_address(imagebase() + phdr_reloc_info_.new_offset);
  nsegment_addr->physical_address(imagebase() + phdr_reloc_info_.new_offset);
  nsegment_addr->flags(ELF_SEGMENT_FLAGS::PF_R);
  nsegment_addr->alignment(0x1000);
  nsegment_addr->file_offset(phdr_reloc_info_.new_offset);
  nsegment_addr->datahandler_ = datahandler_.get();

  DataHandler::Node new_node{phdr_reloc_info_.new_offset, new_phdr_size,
                             DataHandler::Node::SEGMENT};

  datahandler_->add(new_node);

  const auto it_new_segment_place = std::find_if(segments_.rbegin(), segments_.rend(),
      [nsegment_addr] (const std::unique_ptr<Segment>& s) {
        return s->type() == nsegment_addr->type();
      });

  if (it_new_segment_place == segments_.rend()) {
    segments_.push_back(std::move(new_segment_ptr));
  } else {
    const size_t idx = std::distance(std::begin(segments_), it_new_segment_place.base());
    segments_.insert(std::begin(segments_) + idx, std::move(new_segment_ptr));
  }

  this->header().numberof_segments(this->header().numberof_segments() + 1);

  const auto it_segment_phdr = std::find_if(std::begin(segments_), std::end(segments_),
              [] (const std::unique_ptr<Segment>& s) {
                return s->type() == SEGMENT_TYPES::PT_PHDR;
              });

  if (it_segment_phdr != std::end(segments_)) {
    const std::unique_ptr<Segment>& phdr_segment = *it_segment_phdr;
    phdr_segment->file_offset(nsegment_addr->file_offset());
    phdr_segment->virtual_address(nsegment_addr->virtual_address());
    phdr_segment->physical_address(nsegment_addr->physical_address());
    phdr_segment->content(std::vector<uint8_t>(phdr_segment->physical_size(), 0));
  }


  // Shift components that come after the bss offset
  uint64_t from = bss_segment->file_offset() + original_psize;
  uint64_t shift = delta_pa + nb_segments * phdr_size;
  this->header().section_headers_offset(this->header().section_headers_offset() + shift);

  // Shift sections
  for (const std::unique_ptr<Section>& section : sections_) {
    if (section->is_frame()) {
      continue;
    }
    if (section->file_offset() >= from && section->type() != ELF_SECTION_TYPES::SHT_NOBITS) {
      LIEF_DEBUG("[BEFORE] {}", *section);
      section->file_offset(section->file_offset() + shift);
      if (section->virtual_address() > 0) {
        section->virtual_address(section->virtual_address() + shift);
      }
      LIEF_DEBUG("[AFTER ] {}", *section);
    }
  }
  return phdr_reloc_info_.new_offset;
}


uint64_t Binary::relocate_phdr_table_v1() {
  // The minimum number of segments that need to be available
  // to consider this relocation valid
  static constexpr auto MIN_POTENTIAL_SIZE = 2;

  // check if we already relocated the segment table in the larger segment's cave
  if (phdr_reloc_info_.new_offset > 0) {
    return phdr_reloc_info_.new_offset;
  }

  Header& header = this->header();

  const uint64_t phdr_size = type() == ELF_CLASS::ELFCLASS32 ?
                                       sizeof(details::ELF32::Elf_Phdr) :
                                       sizeof(details::ELF64::Elf_Phdr);

  const auto it_segment_phdr = std::find_if(std::begin(segments_), std::end(segments_),
              [] (const std::unique_ptr<Segment>& s) {
                return s->type() == SEGMENT_TYPES::PT_PHDR;
              });

  std::vector<Segment*> load_seg;
  for (std::unique_ptr<Segment>& segment : segments_) {
    if (segment->type() == SEGMENT_TYPES::PT_LOAD) {
      load_seg.push_back(segment.get());
    }
  }

  // Take the 2 adjacent segments that have the larger "cave"
  Segment* seg_to_extend = nullptr;
  Segment* next_to_extend = nullptr;
  size_t potential_size = 0;
  const size_t nb_loads = load_seg.size();

  // This function requires to have at least 2 segments
  if (nb_loads == 1) {
    return 0;
  }

  for (size_t i = 0; i < (nb_loads - 1); ++i) {
    Segment* current = load_seg[i];
    // Skip bss-like segments
    if (current->virtual_size() != current->physical_size()) {
      LIEF_DEBUG("Skipping .bss like segment: {}@0x{:x}:0x{:x}",
                 to_string(current->type()), current->virtual_address(), current->virtual_size());
      continue;
    }
    Segment* adjacent = load_seg[i + 1];
    const size_t gap = adjacent->file_offset() - (current->file_offset() + current->physical_size());
    const size_t nb_seg_gap = gap / phdr_size;
    LIEF_DEBUG("Gap between {:d} <-> {:d}: {:x} ({:d} segments)", i, i + 1, gap, nb_seg_gap);
    if (nb_seg_gap > potential_size) {
      seg_to_extend  = current;
      next_to_extend = adjacent;
      potential_size = nb_seg_gap;
    }
  }

  if (seg_to_extend == nullptr || next_to_extend == nullptr) {
    LIEF_DEBUG("Can't find a suitable segment (v1)");
    return 0;
  }

  if (potential_size < (header.numberof_segments() + MIN_POTENTIAL_SIZE)) {
    LIEF_DEBUG("The number of available segments is too small ({} vs {})",
               potential_size, header.numberof_segments() + MIN_POTENTIAL_SIZE);
    return 0;
  }

  LIEF_DEBUG("Segment selected for the extension: {}@0x{:x}:0x{:x}",
             to_string(seg_to_extend->type()), seg_to_extend->virtual_address(),
             seg_to_extend->virtual_size());

  LIEF_DEBUG("Adjacent segment selected for the extension: {}@0x{:x}:0x{:x}",
             to_string(next_to_extend->type()), next_to_extend->virtual_address(),
             next_to_extend->virtual_size());

  // Extend the segment that wraps the next PHDR table so that it is contiguous
  // with the next segment.
  size_t delta = next_to_extend->file_offset() - (seg_to_extend->file_offset() + seg_to_extend->physical_size());
  const size_t nb_segments = delta / phdr_size - header.numberof_segments();
  if (nb_segments < header.numberof_segments()) {
    LIEF_DEBUG("The layout of this binary does not enable to relocate the segment table (v1)\n"
               "We would need at least {} segments while only {} are available",
               header.numberof_segments(), nb_segments);
    phdr_reloc_info_.clear();
    return 0;
  }


  // New values
  const uint64_t new_phdr_offset = seg_to_extend->file_offset() + seg_to_extend->physical_size();
  phdr_reloc_info_.new_offset = new_phdr_offset;

  header.program_headers_offset(new_phdr_offset);


  phdr_reloc_info_.nb_segments = nb_segments;
  seg_to_extend->physical_size(seg_to_extend->physical_size() + delta);
  seg_to_extend->virtual_size(seg_to_extend->virtual_size() + delta);


  if (it_segment_phdr != std::end(segments_)) {
    const std::unique_ptr<Segment>& phdr_segment = *it_segment_phdr;
    // Update the PHDR segment with our values
    const uint64_t base = seg_to_extend->virtual_address() - seg_to_extend->file_offset();
    phdr_segment->file_offset(new_phdr_offset);
    phdr_segment->virtual_address(base + phdr_segment->file_offset());
    phdr_segment->physical_address(phdr_segment->virtual_address());
    LIEF_DEBUG("{}@0x{:x}:0x{:x}", to_string(phdr_segment->type()),
                                   phdr_segment->virtual_address(), phdr_segment->virtual_size());
    // Clear PHDR segment
    phdr_segment->physical_size(delta);
    phdr_segment->virtual_size(delta);
    phdr_segment->content(std::vector<uint8_t>(delta, 0));
  }
  return phdr_reloc_info_.new_offset;
}

// Operator+=
// ==========
Binary& Binary::operator+=(const DynamicEntry& entry) {
  add(entry);
  return *this;
}

Binary& Binary::operator+=(const Section& section) {
  add(section);
  return *this;
}

Binary& Binary::operator+=(const Segment& segment) {
  add(segment);
  return *this;
}

Binary& Binary::operator+=(const Note& note) {
  add(note);
  return *this;
}

// Operator -=
// ===========
Binary& Binary::operator-=(const DynamicEntry& entry) {
  remove(entry);
  return *this;
}

Binary& Binary::operator-=(DYNAMIC_TAGS tag) {
  remove(tag);
  return *this;
}


Binary& Binary::operator-=(const Note& note) {
  remove(note);
  return *this;
}

Binary& Binary::operator-=(NOTE_TYPES type) {
  remove(type);
  return *this;
}

// Operator[]
// ==========
Segment* Binary::operator[](SEGMENT_TYPES type) {
  return get(type);
}

const Segment* Binary::operator[](SEGMENT_TYPES type) const {
  return get(type);
}

DynamicEntry* Binary::operator[](DYNAMIC_TAGS tag) {
  return get(tag);
}

const DynamicEntry* Binary::operator[](DYNAMIC_TAGS tag) const {
  return get(tag);
}

Note* Binary::operator[](NOTE_TYPES type) {
  return get(type);
}

const Note* Binary::operator[](NOTE_TYPES type) const {
  return get(type);
}

Section* Binary::operator[](ELF_SECTION_TYPES type) {
  return get(type);
}

const Section* Binary::operator[](ELF_SECTION_TYPES type) const {
  return get(type);
}

bool Binary::operator==(const Binary& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Binary::operator!=(const Binary& rhs) const {
  return !(*this == rhs);
}



std::ostream& Binary::print(std::ostream& os) const {

  os << "Header" << std::endl;
  os << "======" << std::endl;

  os << header();
  os << std::endl;


  os << "Sections" << std::endl;
  os << "========" << std::endl;
  for (const Section& section : sections()) {
    os << section << std::endl;
  }
  os << std::endl;


  os << "Segments" << std::endl;
  os << "========" << std::endl;
  for (const Segment& segment : segments()) {
    os << segment << std::endl;
  }

  os << std::endl;


  os << "Dynamic entries" << std::endl;
  os << "===============" << std::endl;

  for (const DynamicEntry& entry : dynamic_entries()) {
    os << entry << std::endl;
  }

  os << std::endl;


  os << "Dynamic symbols" << std::endl;
  os << "===============" << std::endl;

  for (const Symbol& symbol : dynamic_symbols()) {
    os << symbol << std::endl;
  }

  os << std::endl;


  os << "Static symbols" << std::endl;
  os << "==============" << std::endl;

  for (const Symbol& symbol : static_symbols()) {
    os << symbol << std::endl;
  }

  os << std::endl;


  os << "Symbol versions" << std::endl;
  os << "===============" << std::endl;

  for (const SymbolVersion& sv : symbols_version()) {
    os << sv << std::endl;
  }

  os << std::endl;


  os << "Symbol versions definition" << std::endl;
  os << "==========================" << std::endl;

  for (const SymbolVersionDefinition& svd : symbols_version_definition()) {
    os << svd << std::endl;
  }

  os << std::endl;


  os << "Symbol version requirement" << std::endl;
  os << "==========================" << std::endl;

  for (const SymbolVersionRequirement& svr : symbols_version_requirement()) {
    os << svr << std::endl;
  }

  os << std::endl;


  os << "Dynamic relocations" << std::endl;
  os << "===================" << std::endl;

  for (const Relocation& relocation : dynamic_relocations()) {
    os << relocation << std::endl;
  }

  os << std::endl;


  os << ".plt.got relocations" << std::endl;
  os << "====================" << std::endl;

  for (const Relocation& relocation : pltgot_relocations()) {
    os << relocation << std::endl;
  }

  os << std::endl;

  if (notes().size() > 0) {
    os << "Notes" << std::endl;
    os << "=====" << std::endl;

    it_const_notes notes = this->notes();
    for (size_t i = 0; i < notes.size(); ++i) {
      std::string title = "Note #" + std::to_string(i);
      os << title << std::endl;
      os << std::string(title.size(), '-') << std::endl;
      os << notes[i] << std::endl;
    }
    os << std::endl;
  }

  os << std::endl;
  if (use_gnu_hash()) {
    os << "GNU Hash Table" << std::endl;
    os << "==============" << std::endl;

    os << gnu_hash() << std::endl;

    os << std::endl;
  }


  if (use_sysv_hash()) {
    os << "SYSV Hash Table" << std::endl;
    os << "===============" << std::endl;

    os << sysv_hash() << std::endl;

    os << std::endl;
  }



  return os;
}



Binary::~Binary() = default;
}
}
