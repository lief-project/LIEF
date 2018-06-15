/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#else
#define getpagesize() 0x1000
#endif

#include <stdexcept>

#include "LIEF/logging++.hpp"

#include "LIEF/exception.hpp"
#include "LIEF/utils.hpp"

#include "LIEF/ELF/EnumToString.hpp"
#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/Builder.hpp"

#include "LIEF/ELF/hash.hpp"

#include "Binary.tcc"
#include "Object.tcc"

namespace LIEF {
namespace ELF {
Binary::Binary(void)  = default;

Binary::Binary(const std::string& name, ELF_CLASS type) : type_{type} {
  this->name_ = name;
  if (type_ == ELF_CLASS::ELFCLASS32) {
  }
  else if (type_ == ELF_CLASS::ELFCLASS32) {
  }
}


Header& Binary::header(void) {
  return const_cast<Header&>(static_cast<const Binary*>(this)->header());
}


const Header& Binary::header(void) const {
  return this->header_;
}


ELF_CLASS Binary::type(void) const {
  return this->type_;
}

size_t Binary::hash(const std::string& name) {
  if (this->type_ == ELF_CLASS::ELFCLASS32) {
    return hash32(name.c_str());
  } else {
    return hash32(name.c_str());
  }
}

LIEF::sections_t Binary::get_abstract_sections(void) {
  return {std::begin(this->sections_), std::end(this->sections_)};
}


// Sections
// ========

it_sections Binary::sections(void) {
  return this->sections_;
}


it_const_sections Binary::sections(void) const {
  return this->sections_;
}

// Segments
// ========

it_segments Binary::segments(void) {
  return this->segments_;
}

it_const_segments Binary::segments(void) const {
  return this->segments_;
}


std::vector<std::string> Binary::get_abstract_exported_functions(void) const {
  std::vector<std::string> result;
  for (const Symbol& symbol : this->exported_symbols()) {
    if (symbol.type() == ELF_SYMBOL_TYPES::STT_FUNC) {
      result.push_back(symbol.name());
    }
  }
  return result;
}


std::vector<std::string> Binary::get_abstract_imported_functions(void) const {
  std::vector<std::string> result;
  for (const Symbol& symbol : this->imported_symbols()) {
    if (symbol.type() == ELF_SYMBOL_TYPES::STT_FUNC) {
      result.push_back(symbol.name());
    }
  }
  return result;
}


std::vector<std::string> Binary::get_abstract_imported_libraries(void) const {
  std::vector<std::string> result;
  for (const DynamicEntry& entry : this->dynamic_entries()) {
    if (dynamic_cast<const DynamicEntryLibrary*>(&entry)) {
      result.push_back(dynamic_cast<const DynamicEntryLibrary*>(&entry)->name());
    }
  }
  return result;
}


// Dynamic Entries
// ===============

it_dynamic_entries Binary::dynamic_entries(void) {
  return this->dynamic_entries_;
}

it_const_dynamic_entries Binary::dynamic_entries(void) const {
  return this->dynamic_entries_;
}


DynamicEntry& Binary::add(const DynamicEntry& entry) {

  DynamicEntry* new_one = nullptr;
  switch (entry.tag()) {
    case DYNAMIC_TAGS::DT_NEEDED:
      {
        new_one = new DynamicEntryLibrary{*dynamic_cast<const DynamicEntryLibrary*>(&entry)};
        break;
      }


    case DYNAMIC_TAGS::DT_SONAME:
      {
        new_one = new DynamicSharedObject{*dynamic_cast<const DynamicSharedObject*>(&entry)};
        break;
      }


    case DYNAMIC_TAGS::DT_RPATH:
      {
        new_one = new DynamicEntryRpath{*dynamic_cast<const DynamicEntryRpath*>(&entry)};
        break;
      }


    case DYNAMIC_TAGS::DT_RUNPATH:
      {
        new_one = new DynamicEntryRunPath{*dynamic_cast<const DynamicEntryRunPath*>(&entry)};
        break;
      }


    case DYNAMIC_TAGS::DT_FLAGS_1:
    case DYNAMIC_TAGS::DT_FLAGS:
      {
        new_one = new DynamicEntryFlags{*dynamic_cast<const DynamicEntryFlags*>(&entry)};
        break;
      }


    case DYNAMIC_TAGS::DT_FINI_ARRAY:
    case DYNAMIC_TAGS::DT_INIT_ARRAY:
    case DYNAMIC_TAGS::DT_PREINIT_ARRAY:
      {
        new_one = new DynamicEntryArray{*dynamic_cast<const DynamicEntryArray*>(&entry)};
        break;
      }

    default:
      {
        new_one = new DynamicEntry{entry};
      }
  }

  auto&& it_new_place = std::find_if(
      std::begin(this->dynamic_entries_),
      std::end(this->dynamic_entries_),
      [&new_one] (const DynamicEntry* e) {
        return e->tag() == new_one->tag() or e->tag() == DYNAMIC_TAGS::DT_NULL;
      });

  this->dynamic_entries_.insert(it_new_place, new_one);
  return *new_one;

}


Note& Binary::add(const Note& note) {
  this->notes_.emplace_back(new Note{note});
  return *this->notes_.back();
}


void Binary::remove(const DynamicEntry& entry) {
  auto&& it_entry = std::find_if(
      std::begin(this->dynamic_entries_),
      std::end(this->dynamic_entries_),
      [&entry] (const DynamicEntry* e) {
        return *e == entry;
      });

  if (it_entry == std::end(this->dynamic_entries_)) {
    std::stringstream ss;
    ss << entry;
    throw not_found("Can't find '" + ss.str() +  "' in the dynamic table!");
  }

  delete *it_entry;
  this->dynamic_entries_.erase(it_entry);
}


void Binary::remove(DYNAMIC_TAGS tag) {
  for (auto&& it = std::begin(this->dynamic_entries_);
              it != std::end(this->dynamic_entries_);) {
    if ((*it)->tag() == tag) {
      delete *it;
      it = this->dynamic_entries_.erase(it);
    } else {
      ++it;
    }
  }
}

void Binary::remove(const Section& section, bool clear) {
  auto&& it_section = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [&section] (const Section* s) {
        return *s == section;
      });

  if (it_section == std::end(this->sections_)) {
    throw not_found("Can't find '" + section.name() +  "'!");
  }

  size_t idx = std::distance(it_section, std::end(this->sections_));

  Section* s = *it_section;

  // Remove from segments:
  for (Segment* segment : this->segments_) {
    auto&& sections = segment->sections_;
    sections.erase(std::remove_if(
          std::begin(sections),
          std::end(sections),
          [&s] (Section* sec) { return *sec == *s; }),
          std::end(sections));
  }

  if (clear) {
    s->clear(0);
  }

  this->datahandler_->remove(s->file_offset(), s->size(), DataHandler::Node::SECTION);

  // Patch header
  this->header().numberof_sections(this->header().numberof_sections() - 1);

  if (idx < this->header().section_name_table_idx()) {
    this->header().section_name_table_idx(this->header().section_name_table_idx() - 1);
  }

  delete s;
  this->sections_.erase(it_section);
}

void Binary::remove(const Note& note) {

  auto&& it_note = std::find_if(
      std::begin(this->notes_),
      std::end(this->notes_),
      [&note] (const Note* n)
      {
        return note == *n;
      });

  if (it_note == std::end(this->notes_)) {
    throw not_found(std::string("Can't find note '") + to_string(static_cast<NOTE_TYPES>(note.type())) +  "'!");
  }
  delete *it_note;
  this->notes_.erase(it_note);
}

void Binary::remove(NOTE_TYPES type) {
  for (auto&& it = std::begin(this->notes_);
              it != std::end(this->notes_);) {
    Note* n = *it;
    if (static_cast<NOTE_TYPES>(n->type()) == type) {
      delete n;
      it = this->notes_.erase(it);
    } else {
      ++it;
    }
  }
}



// Symbols
// =======

// Statics
// -------

it_symbols Binary::static_symbols(void) {
  return this->static_symbols_;
}

it_const_symbols Binary::static_symbols(void) const {
  return this->static_symbols_;
}

// Dynamics
// --------

it_symbols Binary::dynamic_symbols(void) {
  return this->dynamic_symbols_;
}

it_const_symbols Binary::dynamic_symbols(void) const {
  return this->dynamic_symbols_;
}


it_symbols Binary::symbols(void) {
  return this->static_dyn_symbols();
}

it_const_symbols Binary::symbols(void) const {
  return this->static_dyn_symbols();
}


Symbol& Binary::export_symbol(const Symbol& symbol) {

  // Chck if the symbol is in the dynamic symbol table
  auto&& it_symbol = std::find_if(
      std::begin(this->dynamic_symbols_),
      std::end(this->dynamic_symbols_),
      [&symbol] (const Symbol* s) {
        return *s == symbol;
      });

  if (it_symbol == std::end(this->dynamic_symbols_)) {
    // Create a new one
    Symbol& new_sym = this->add_dynamic_symbol(symbol, SymbolVersion::local());
    return this->export_symbol(new_sym);
  }

  auto&& it_text = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [] (const Section* s) {
        return s->name() == ".text";
      });
  size_t text_idx = std::distance(std::begin(this->sections_), it_text);

  Symbol& s = **it_symbol;
  if (s.binding() != SYMBOL_BINDINGS::STB_WEAK or s.binding() != SYMBOL_BINDINGS::STB_GLOBAL) {
    s.binding(SYMBOL_BINDINGS::STB_GLOBAL);
  }

  if (s.type() == ELF_SYMBOL_TYPES::STT_NOTYPE) {
    s.type(ELF_SYMBOL_TYPES::STT_COMMON);
  }

  if (s.shndx() == 0) {
    s.shndx(text_idx);
  }

  s.visibility(ELF_SYMBOL_VISIBILITY::STV_DEFAULT);
  return s;
}

Symbol& Binary::export_symbol(const std::string& symbol_name, uint64_t value) {
  if (this->has_dynamic_symbol(symbol_name)) {
    Symbol& s = this->get_dynamic_symbol(symbol_name);
    if (value > 0) {
      s.value(value);
    }
    return this->export_symbol(s);
  }

  if (this->has_static_symbol(symbol_name)) {
    Symbol& s = this->get_static_symbol(symbol_name);
    if (value > 0) {
      s.value(value);
    }
    return this->export_symbol(s);
  }

  // Create a new one
  Symbol newsym;
  newsym.name(symbol_name);
  newsym.type(ELF_SYMBOL_TYPES::STT_COMMON);
  newsym.binding(SYMBOL_BINDINGS::STB_GLOBAL);
  newsym.visibility(ELF_SYMBOL_VISIBILITY::STV_DEFAULT);
  newsym.value(value);
  return this->export_symbol(newsym);
}


Symbol& Binary::add_exported_function(uint64_t address, const std::string& name) {
  std::string funcname = name;
  if (funcname.size() == 0) {
    std::stringstream ss;
    ss << "func_" << std::hex << address;
    funcname = ss.str();
  }

  // First: Check if a symbol with the given 'name' exists in the **dynamic** table
  if (this->has_dynamic_symbol(funcname)) {
    Symbol& s = this->get_dynamic_symbol(funcname);
    s.type(ELF_SYMBOL_TYPES::STT_FUNC);
    s.binding(SYMBOL_BINDINGS::STB_GLOBAL);
    s.visibility(ELF_SYMBOL_VISIBILITY::STV_DEFAULT);
    s.value(address);
    return this->export_symbol(s);
  }

  // Second: Check if a symbol with the given 'name' exists in the **static**
  if (this->has_static_symbol(funcname)) {
    Symbol& s = this->get_static_symbol(funcname);
    s.type(ELF_SYMBOL_TYPES::STT_FUNC);
    s.binding(SYMBOL_BINDINGS::STB_GLOBAL);
    s.visibility(ELF_SYMBOL_VISIBILITY::STV_DEFAULT);
    s.value(address);
    return this->export_symbol(s);
  }

  // Create a new Symbol
  Symbol funcsym;
  funcsym.name(funcname);
  funcsym.type(ELF_SYMBOL_TYPES::STT_FUNC);
  funcsym.binding(SYMBOL_BINDINGS::STB_GLOBAL);
  funcsym.visibility(ELF_SYMBOL_VISIBILITY::STV_DEFAULT);
  funcsym.value(address);

  return this->export_symbol(funcsym);

}


bool Binary::has_dynamic_symbol(const std::string& name) const {
  auto&& it_symbol = std::find_if(
      std::begin(this->dynamic_symbols_),
      std::end(this->dynamic_symbols_),
      [&name] (const Symbol* s) {
        return s->name() == name;
      });
  return it_symbol != std::end(this->dynamic_symbols_);
}

const Symbol& Binary::get_dynamic_symbol(const std::string& name) const {
  if (not this->has_dynamic_symbol(name)) {
    throw not_found("Symbol '" + name + "' not found!");
  }

  auto&& it_symbol = std::find_if(
      std::begin(this->dynamic_symbols_),
      std::end(this->dynamic_symbols_),
      [&name] (const Symbol* s) {
        return s->name() == name;
      });
  return **it_symbol;
}

Symbol& Binary::get_dynamic_symbol(const std::string& name) {
  return const_cast<Symbol&>(static_cast<const Binary*>(this)->get_dynamic_symbol(name));
}

bool Binary::has_static_symbol(const std::string& name) const {
  auto&& it_symbol = std::find_if(
      std::begin(this->static_symbols_),
      std::end(this->static_symbols_),
      [&name] (const Symbol* s) {
        return s->name() == name;
      });
  return it_symbol != std::end(this->static_symbols_);
}

const Symbol& Binary::get_static_symbol(const std::string& name) const {
  if (not this->has_static_symbol(name)) {
    throw not_found("Symbol '" + name + "' not found!");
  }

  auto&& it_symbol = std::find_if(
      std::begin(this->static_symbols_),
      std::end(this->static_symbols_),
      [&name] (const Symbol* s) {
        return s->name() == name;
      });
  return **it_symbol;

}

Symbol& Binary::get_static_symbol(const std::string& name) {
  return const_cast<Symbol&>(static_cast<const Binary*>(this)->get_static_symbol(name));
}


symbols_t Binary::static_dyn_symbols(void) const {
  symbols_t symbols;
  symbols.reserve(this->dynamic_symbols().size() + this->static_symbols().size());
  for (Symbol& s : this->dynamic_symbols()) {
    symbols.push_back(&s);
  }

  for (Symbol& s : this->static_symbols()) {
    symbols.push_back(&s);
  }
  return symbols;
}

// Exported
// --------

it_exported_symbols Binary::exported_symbols(void) {

  return {this->static_dyn_symbols(),
    [] (const Symbol* symbol) { return symbol->is_exported(); }
  };
}

it_const_exported_symbols Binary::exported_symbols(void) const {
  return {this->static_dyn_symbols(),
    [] (const Symbol* symbol) { return symbol->is_exported(); }
  };
}



// Imported
// --------

it_imported_symbols Binary::imported_symbols(void) {
  return {this->static_dyn_symbols(),
    [] (const Symbol* symbol) { return symbol->is_imported(); }
  };
}

it_const_imported_symbols Binary::imported_symbols(void) const {
  return {this->static_dyn_symbols(),
    [] (const Symbol* symbol) { return symbol->is_imported(); }
  };
}


// Symbol version
// --------------

it_symbols_version Binary::symbols_version(void) {
  return this->symbol_version_table_;
}

it_const_symbols_version Binary::symbols_version(void) const {
  return this->symbol_version_table_;
}

// Symbol version definition
// -------------------------

it_symbols_version_definition Binary::symbols_version_definition(void) {
  return this->symbol_version_definition_;
}

it_const_symbols_version_definition Binary::symbols_version_definition(void) const {
  return this->symbol_version_definition_;
}

// Symbol version requirement
// --------------------------

it_symbols_version_requirement Binary::symbols_version_requirement(void) {
  return this->symbol_version_requirements_;
}

it_const_symbols_version_requirement Binary::symbols_version_requirement(void) const {
  return this->symbol_version_requirements_;
}

void Binary::remove_symbol(const std::string& name) {
  this->remove_static_symbol(name);
  this->remove_dynamic_symbol(name);
}


void Binary::remove_static_symbol(const std::string& name) {
  auto&& it_symbol = std::find_if(
      std::begin(this->static_symbols_),
      std::end(this->static_symbols_),
      [&name] (const Symbol* symbol) {
        return symbol != nullptr and symbol->name() == name;
      });

  if (it_symbol == std::end(this->static_symbols_)) {
    throw not_found("Can't find '" + name + "'");
  }

  this->remove_static_symbol(*it_symbol);

}

void Binary::remove_static_symbol(Symbol* symbol) {
  auto&& it_symbol = std::find_if(
      std::begin(this->static_symbols_),
      std::end(this->static_symbols_),
      [&symbol] (const Symbol* sym) {
        return sym != nullptr and sym != nullptr and *symbol == *sym;
      });

  if (it_symbol == std::end(this->static_symbols_)) {
    throw not_found("Can't find '" + symbol->name() + "'");
  }

  delete *it_symbol;
  this->dynamic_symbols_.erase(it_symbol);

  symbol = nullptr;

}



void Binary::remove_dynamic_symbol(const std::string& name) {
  auto&& it_symbol = std::find_if(
      std::begin(this->dynamic_symbols_),
      std::end(this->dynamic_symbols_),
      [&name] (const Symbol* symbol) {
        return symbol != nullptr and symbol->name() == name;
      });

  if (it_symbol == std::end(this->dynamic_symbols_)) {
    throw not_found("Can't find '" + name + "'");
  }

  this->remove_dynamic_symbol(*it_symbol);

}

void Binary::remove_dynamic_symbol(Symbol* symbol) {
  auto&& it_symbol = std::find_if(
      std::begin(this->dynamic_symbols_),
      std::end(this->dynamic_symbols_),
      [&symbol] (const Symbol* sym) {
        return symbol != nullptr and sym != nullptr and *symbol == *sym;
      });

  if (it_symbol == std::end(this->dynamic_symbols_)) {
    throw not_found("Can't find '" + symbol->name() + "'");
  }


  // Update relocations
  auto&& it_relocation = std::find_if(
      std::begin(this->relocations_),
      std::end(this->relocations_),
      [&symbol] (const Relocation* relocation) {
        return relocation != nullptr and
        relocation->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_PLTGOT and
        relocation->has_symbol() and
        relocation->symbol() == *symbol;
      });

  if (it_relocation != std::end(this->relocations_)) {
    delete *it_relocation;
    this->relocations_.erase(it_relocation);
  } else {
  }


  it_relocation = std::find_if(
      std::begin(this->relocations_),
      std::end(this->relocations_),
      [&symbol] (const Relocation* relocation) {
        return relocation != nullptr and
        relocation->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_DYNAMIC and
        relocation->has_symbol() and
        relocation->symbol() == *symbol;
      });

  if (it_relocation != std::end(this->relocations_)) {
    delete *it_relocation;
    this->relocations_.erase(it_relocation);
  }

  // Update symbol versions
  if (symbol->has_version()) {
    this->symbol_version_table_.erase(
        std::remove(
          std::begin(this->symbol_version_table_),
          std::end(this->symbol_version_table_),
          symbol->symbol_version_));
    delete symbol->symbol_version_;

  }

  delete *it_symbol;
  this->dynamic_symbols_.erase(it_symbol);

  symbol = nullptr;

}


// Relocations
// ===========

// Dynamics
// --------

it_dynamic_relocations Binary::dynamic_relocations(void) {
  return filter_iterator<relocations_t>{std::ref(this->relocations_),
    [] (const Relocation* reloc) {
      return reloc->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_DYNAMIC;
    }
  };
}

it_const_dynamic_relocations Binary::dynamic_relocations(void) const {
  return const_filter_iterator<const relocations_t>{std::cref(this->relocations_),
    [] (const Relocation* reloc) {
      return reloc->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_DYNAMIC;
    }
  };
}


Relocation& Binary::add_dynamic_relocation(const Relocation& relocation) {
  Relocation* relocation_ptr = new Relocation{relocation};
  relocation_ptr->purpose(RELOCATION_PURPOSES::RELOC_PURPOSE_DYNAMIC);
  relocation_ptr->architecture_ = this->header().machine_type();
  this->relocations_.push_back(relocation_ptr);

  // Update the Dynamic Section (Thanks to @yd0b0N)
  bool is_rela = relocation.is_rela();
  DYNAMIC_TAGS tag_sz  = is_rela ? DYNAMIC_TAGS::DT_RELASZ  : DYNAMIC_TAGS::DT_RELSZ;
  DYNAMIC_TAGS tag_ent = is_rela ? DYNAMIC_TAGS::DT_RELAENT : DYNAMIC_TAGS::DT_RELENT;

  if (this->has(tag_sz) and this->has(tag_ent)) {
   DynamicEntry &dt_sz  = this->get(tag_sz);
   DynamicEntry &dt_ent = this->get(tag_ent);
   dt_sz.value(dt_sz.value() + dt_ent.value());
  }

  return *relocation_ptr;
}


Relocation& Binary::add_pltgot_relocation(const Relocation& relocation) {
  Relocation* relocation_ptr = new Relocation{relocation};
  relocation_ptr->purpose(RELOCATION_PURPOSES::RELOC_PURPOSE_PLTGOT);
  relocation_ptr->architecture_ = this->header().machine_type();
  this->relocations_.push_back(relocation_ptr);
  return *relocation_ptr;
}

// plt/got
// -------
it_pltgot_relocations Binary::pltgot_relocations(void) {
  return filter_iterator<relocations_t>{std::ref(this->relocations_),
    [] (const Relocation* reloc) {
      return reloc->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_PLTGOT;
    }
  };
}

it_const_pltgot_relocations Binary::pltgot_relocations(void) const {
  return const_filter_iterator<const relocations_t>{std::cref(this->relocations_),
    [] (const Relocation* reloc) {
      return reloc->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_PLTGOT;
    }
  };
}


// objects
// -------
it_object_relocations Binary::object_relocations(void) {
  return filter_iterator<relocations_t>{std::ref(this->relocations_),
    [] (const Relocation* reloc) {
      return reloc->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_OBJECT;
    }
  };
}

it_const_object_relocations Binary::object_relocations(void) const {
  return const_filter_iterator<const relocations_t>{std::cref(this->relocations_),
    [] (const Relocation* reloc) {
      return reloc->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_OBJECT;
    }
  };
}

// All relocations
// ---------------
it_relocations Binary::relocations(void) {
  return this->relocations_;
}

it_const_relocations Binary::relocations(void) const {
  return this->relocations_;
}

LIEF::relocations_t Binary::get_abstract_relocations(void) {
  LIEF::relocations_t relocations;
  relocations.reserve(this->relocations_.size());
  std::copy(
      std::begin(this->relocations_),
      std::end(this->relocations_),
      std::back_inserter(relocations));

  return relocations;
}


LIEF::symbols_t Binary::get_abstract_symbols(void) {
  LIEF::symbols_t symbols;
  symbols.reserve(this->dynamic_symbols_.size() + this->static_symbols_.size());
  std::copy(
      std::begin(this->dynamic_symbols_),
      std::end(this->dynamic_symbols_),
      std::back_inserter(symbols));

  std::copy(
      std::begin(this->static_symbols_),
      std::end(this->static_symbols_),
      std::back_inserter(symbols));
  return symbols;

}


Section& Binary::get_section(const std::string& name) {
  return const_cast<Section&>(static_cast<const Binary*>(this)->get_section(name));
}

const Section& Binary::get_section(const std::string& name) const {
  auto&& it_section = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [&name] (const Section* section)
      {
        return section != nullptr and section->name() == name;
      });

  if (it_section == std::end(this->sections_)) {
    throw not_found("Unable to find section '" + name + "'");
  }
  return **it_section;

}

Section& Binary::text_section(void) {
  return this->get_section(".text");
}


Section& Binary::dynamic_section(void) {

  auto&& it_dynamic_section = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [] (const Section* section) {
        return section != nullptr and section->type() == ELF_SECTION_TYPES::SHT_DYNAMIC;
      });

  if (it_dynamic_section == std::end(this->sections_)) {
    throw not_found("Unable to find the SHT_DYNAMIC section");
  }

  return **it_dynamic_section;

}

Section& Binary::hash_section(void) {
  auto&& it_hash_section = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [] (const Section* section) {
        return section != nullptr and (section->type() == ELF_SECTION_TYPES::SHT_HASH or
            section->type() == ELF_SECTION_TYPES::SHT_GNU_HASH);
      });

  if (it_hash_section == std::end(this->sections_)) {
    throw not_found("Unable to find the SHT_HASH / SHT_GNU_HASH section");
  }

  return **it_hash_section;

}

Section& Binary::static_symbols_section(void) {

  auto&& it_symtab_section = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [] (const Section* section)
      {
        return section != nullptr and section->type() == ELF_SECTION_TYPES::SHT_SYMTAB;
      });


  if (it_symtab_section == std::end(this->sections_)) {
    throw not_found("Unable to find a SHT_SYMTAB section");
  }

  return **it_symtab_section;
}

uint64_t Binary::imagebase(void) const {
  uint64_t imagebase = static_cast<uint64_t>(-1);
  for (const Segment* segment : this->segments_) {
    if (segment != nullptr and segment->type() == SEGMENT_TYPES::PT_LOAD) {
      imagebase = std::min(imagebase, segment->virtual_address() - segment->file_offset());
    }
  }
  return imagebase;
}

uint64_t Binary::virtual_size(void) const {
  uint64_t virtual_size = 0;
  for (const Segment* segment : this->segments_) {
    if (segment != nullptr and segment->type() == SEGMENT_TYPES::PT_LOAD) {
      virtual_size = std::max(virtual_size, segment->virtual_address() + segment->virtual_size());
    }
  }
  virtual_size = align(virtual_size, static_cast<uint64_t>(getpagesize()));
  return virtual_size - this->imagebase();
}


std::vector<uint8_t> Binary::raw(void) {
  Builder builder{this};
  builder.build();
  return builder.get_build();
}


uint64_t Binary::get_function_address(const std::string& func_name) const {
  try {
    return this->get_function_address(func_name, true);
  } catch(const not_found&) {
    return this->get_function_address(func_name, false);
  } catch(const not_supported&) {
    return this->get_function_address(func_name, false);
  }
}

uint64_t Binary::get_function_address(const std::string& func_name, bool demangled) const {
  auto&& it_symbol = std::find_if(
      std::begin(this->static_symbols_),
      std::end(this->static_symbols_),
      [&func_name, &demangled] (const Symbol* symbol) {
        if (symbol == nullptr) {
          return false;
        }

        if (demangled) {
          return (symbol->demangled_name() == func_name and
                  symbol->type() == ELF_SYMBOL_TYPES::STT_FUNC);
        } else {
          return (symbol->name() == func_name and
                  symbol->type() == ELF_SYMBOL_TYPES::STT_FUNC);
        }
      });

  if (it_symbol == std::end(this->static_symbols_)) {
    throw not_found("Can't find the function name");
  } else {
    return (*it_symbol)->value();
  }
}

Section& Binary::add(const Section& section, bool loaded) {
  if (loaded) {
    return this->add_section<true>(section);
  } else {
    return this->add_section<false>(section);
  }
}



bool Binary::is_pie(void) const {
  auto&& it_segment = std::find_if(
      std::begin(this->segments_),
      std::end(this->segments_),
      [] (const Segment* entry) {
        return entry != nullptr and entry->type() == SEGMENT_TYPES::PT_INTERP;
      });

  if (it_segment != std::end(this->segments_) and
      this->header().file_type() == E_TYPE::ET_DYN) {
    return true;
  } else {
    return false;
  }
}


bool Binary::has_nx(void) const {
  auto&& it_stack = std::find_if(
      std::begin(this->segments_),
      std::end(this->segments_),
      [] (Segment* segment) {
        return segment != nullptr and segment->type() == SEGMENT_TYPES::PT_GNU_STACK;
      });
  if (it_stack == std::end(this->segments_)) {
    return false;
  }

  return not (*it_stack)->has(ELF_SEGMENT_FLAGS::PF_X);

}

Segment& Binary::add(const Segment& segment, uint64_t base) {
  uint64_t new_base = base;

  if (new_base == 0) {
    new_base = this->next_virtual_address();
  }

  switch(this->header().file_type()) {
    case E_TYPE::ET_EXEC:
      {
        return this->add_segment<E_TYPE::ET_EXEC>(segment, new_base);
        break;
      }

    case E_TYPE::ET_DYN:
      {
        return this->add_segment<E_TYPE::ET_DYN>(segment, new_base);
        break;
      }

    default:
      {
        throw not_implemented(std::string("Adding segment for ") + to_string(this->header().file_type()) + " is not implemented");
      }
  }
}


Segment& Binary::replace(const Segment& new_segment, const Segment& original_segment, uint64_t base) {

  auto&& it_original_segment = std::find_if(
      std::begin(this->segments_),
      std::end(this->segments_),
      [&original_segment] (const Segment* s) {
        return *s == original_segment;
      });

  if (it_original_segment == std::end(this->segments_)) {
    throw not_found("Unable to find the segment in the current binary");
  }


  uint64_t new_base = base;

  if (new_base == 0) {
    new_base = this->next_virtual_address();
  }

  std::vector<uint8_t> content = new_segment.content();
  Segment* new_segment_ptr = new Segment{new_segment};
  new_segment_ptr->datahandler_ = this->datahandler_;

  DataHandler::Node new_node{
          new_segment_ptr->file_offset(),
          new_segment_ptr->physical_size(),
          DataHandler::Node::SEGMENT};
  this->datahandler_->add(new_node);

  const uint64_t last_offset_sections = this->last_offset_section();
  const uint64_t last_offset_segments = this->last_offset_segment();
  const uint64_t last_offset          = std::max<uint64_t>(last_offset_sections, last_offset_segments);

  const uint64_t psize = static_cast<uint64_t>(getpagesize());
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

  this->datahandler_->make_hole(last_offset_aligned, new_segment_ptr->physical_size());
  new_segment_ptr->content(content);


  auto&& it_segment_phdr = std::find_if(
      std::begin(this->segments_),
      std::end(this->segments_),
      [] (const Segment* s)
      {
        return s != nullptr and s->type() == SEGMENT_TYPES::PT_PHDR;
      });

  if (it_segment_phdr != std::end(this->segments_)) {
    Segment *phdr_segment = *it_segment_phdr;
    const size_t phdr_size = phdr_segment->content().size();
    phdr_segment->content(std::vector<uint8_t>(phdr_size, 0));
  }

  // Remove
  Segment* local_original_segment = *it_original_segment;
  this->datahandler_->remove(local_original_segment->file_offset(), local_original_segment->physical_size(), DataHandler::Node::SEGMENT);

  delete local_original_segment;
  this->segments_.erase(it_original_segment);

  // Patch shdr
  Header& header = this->header();
  const uint64_t new_section_hdr_offset = new_segment_ptr->file_offset() + new_segment_ptr->physical_size();
  header.section_headers_offset(new_section_hdr_offset);

  this->segments_.push_back(new_segment_ptr);
  return *this->segments_.back();


}


Segment& Binary::extend(const Segment& segment, uint64_t size) {
  const SEGMENT_TYPES type = segment.type();
  switch (type) {
    case SEGMENT_TYPES::PT_PHDR:
    case SEGMENT_TYPES::PT_LOAD:
      {
        return this->extend_segment<SEGMENT_TYPES::PT_LOAD>(segment, size);
        break;
      }

    default:
      {
        throw not_implemented(std::string("Extending segment '") + to_string(type) + "' is not implemented");
      }
  }
}


Section& Binary::extend(const Section& section, uint64_t size) {
  auto&& it_section = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [&section] (const Section* s) {
        return *s == section;
      });

  if (it_section == std::end(this->sections_)) {
    throw not_found("Unable to find the section " + section.name() + " in the current binary");
  }


  Section* section_to_extend = *it_section;

  uint64_t from_offset  = section_to_extend->offset() + section_to_extend->size();
  uint64_t from_address = section_to_extend->virtual_address() + size;
  uint64_t shift        = size;

  this->datahandler_->make_hole(
      section_to_extend->offset() + section_to_extend->size(),
      size);

  this->shift_sections(from_offset, shift);
  this->shift_segments(from_offset, shift);


  // Patch segment size for the segment which contains the new segment
  for (Segment* segment : this->segments_) {
    if ((segment->file_offset() + segment->physical_size()) >= from_offset and
        from_offset >= segment->file_offset()) {
      segment->virtual_size(segment->virtual_size()   + shift);
      segment->physical_size(segment->physical_size() + shift);
    }
  }


  section_to_extend->size(section_to_extend->size() + size);

  std::vector<uint8_t> section_content = section_to_extend->content();
  section_content.resize(section_to_extend->size(), 0);
  section_to_extend->content(section_content);


  this->header().section_headers_offset(this->header().section_headers_offset() + shift);

  this->shift_dynamic_entries(from_address, shift);
  this->shift_symbols(from_address, shift);
  this->shift_relocations(from_address, shift);


  if (this->header().entrypoint() >= from_address) {
    this->header().entrypoint(this->header().entrypoint() + shift);
  }

  return *section_to_extend;
}

// Patch
// =====

void Binary::patch_address(uint64_t address, const std::vector<uint8_t>& patch_value, LIEF::Binary::VA_TYPES) {
  // Find the segment associated with the virtual address
  Segment& segment_topatch = this->segment_from_virtual_address(address);
  const uint64_t offset = address - segment_topatch.virtual_address();
  std::vector<uint8_t> content = segment_topatch.content();
  if ((offset + patch_value.size()) > content.size()) {
    content.resize(offset + patch_value.size());
  }
  std::copy(
      std::begin(patch_value),
      std::end(patch_value),
      content.data() + offset);
  segment_topatch.content(content);
}


void Binary::patch_address(uint64_t address, uint64_t patch_value, size_t size, LIEF::Binary::VA_TYPES) {
  if (size > sizeof(patch_value)) {
    throw std::runtime_error("Invalid size (" + std::to_string(size) + ")");
  }

  Segment& segment_topatch = this->segment_from_virtual_address(address);
  const uint64_t offset = address - segment_topatch.virtual_address();
  std::vector<uint8_t> content = segment_topatch.content();

  // TODO: Handle Endiness
  std::copy(
      reinterpret_cast<uint8_t*>(&patch_value),
      reinterpret_cast<uint8_t*>(&patch_value) + size,
      content.data() + offset);
  segment_topatch.content(content);
}



void Binary::patch_pltgot(const Symbol& symbol, uint64_t address) {
  it_pltgot_relocations pltgot_relocations = this->pltgot_relocations();
  auto&& it_relocation = std::find_if(
      std::begin(pltgot_relocations),
      std::end(pltgot_relocations),
      [&symbol] (const Relocation& relocation) {
        return relocation.has_symbol() and relocation.symbol() == symbol;
      });

  if (it_relocation == std::end(pltgot_relocations)) {
    throw not_found("Unable to find the relocation associated with symbol '" + symbol.name() + "'");
  }

  uint64_t got_address = (*it_relocation).address();
  this->patch_address(got_address, address, sizeof(uint64_t));
}

void Binary::patch_pltgot(const std::string& symbol_name, uint64_t address) {
  std::for_each(
      std::begin(this->dynamic_symbols_),
      std::end(this->dynamic_symbols_),
      [&symbol_name, address, this] (const Symbol* s) {
        if (s->name() == symbol_name) {
          this->patch_pltgot(*s, address);
        }
      });
}


const Segment& Binary::segment_from_virtual_address(uint64_t address) const {
  auto&& it_segment = std::find_if(
      this->segments_.cbegin(),
      this->segments_.cend(),
      [&address] (const Segment* segment) {
        if (segment == nullptr) {
          return false;
        }
        return ((segment->virtual_address() <= address) and
            (segment->virtual_address() + segment->virtual_size()) > address);
      });

  if (it_segment == this->segments_.cend()) {
    std::stringstream adr_str;
    adr_str << "0x" << std::hex << address;
    throw not_found("Unable to find the segment associated with the address: " + adr_str.str());
  }

  return **it_segment;

}

Segment& Binary::segment_from_virtual_address(uint64_t address) {
  return const_cast<Segment&>(static_cast<const Binary*>(this)->segment_from_virtual_address(address));
}


const Segment& Binary::segment_from_offset(uint64_t offset) const {
  auto&& it_segment = std::find_if(
      this->segments_.cbegin(),
      this->segments_.cend(),
      [&offset] (const Segment* segment) {
        if (segment == nullptr) {
          return false;
        }

        return ((segment->file_offset() <= offset) and
            (segment->file_offset() + segment->physical_size()) > offset);
      });

  if (it_segment == this->segments_.cend()) {
    throw not_found("Unable to find the segment");
  }

  return **it_segment;
}

Segment& Binary::segment_from_offset(uint64_t offset) {
  return const_cast<Segment&>(static_cast<const Binary*>(this)->segment_from_offset(offset));
}

void Binary::remove_section(const std::string& name, bool clear) {
  this->remove(this->get_section(name), clear);
}

bool Binary::has_section(const std::string& name) const {
  return std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [&name] (const Section* section) {
        return section != nullptr and section->name() == name;
      }) != std::end(this->sections_);
}

void Binary::strip(void) {
  this->static_symbols_ = {};

  //for (Section* sec : this->sections_) {
  //  if (sec->segments().size() == 0 and sec->name() != ".shstrtab" and sec->type() != ELF_SECTION_TYPES::SHT_NULL) {
  //    this->remove(*sec, /* clear */ true);
  //    return strip();
  //  }
  //}
  if (this->has(ELF_SECTION_TYPES::SHT_SYMTAB)) {
    Section& symtab = this->get(ELF_SECTION_TYPES::SHT_SYMTAB);
    this->remove(symtab, /* clear */ true);
  }
}


Symbol& Binary::add_static_symbol(const Symbol& symbol) {
  this->static_symbols_.push_back(new Symbol{symbol});
  return *(this->static_symbols_.back());
}


Symbol& Binary::add_dynamic_symbol(const Symbol& symbol, const SymbolVersion& version) {
  Symbol* sym = new Symbol{symbol};
  SymbolVersion* symver = new SymbolVersion{version};
  sym->symbol_version_ = symver;

  this->dynamic_symbols_.push_back(sym);
  this->symbol_version_table_.push_back(symver);
  return *(this->dynamic_symbols_.back());
}

uint64_t Binary::virtual_address_to_offset(uint64_t virtual_address) const {
  auto&& it_segment = std::find_if(
      std::begin(this->segments_),
      std::end(this->segments_),
      [virtual_address] (const Segment* segment)
      {
        if (segment == nullptr) {
          return false;
        }
        return (
          segment->type() == SEGMENT_TYPES::PT_LOAD and
          segment->virtual_address() <= virtual_address and
          segment->virtual_address() + segment->virtual_size() >= virtual_address
          );
      });

  if (it_segment == std::end(this->segments_)) {
    VLOG(VDEBUG) << "Address: 0x" << std::hex << virtual_address;
    throw conversion_error("Invalid virtual address");
  }
  uint64_t baseAddress = (*it_segment)->virtual_address() - (*it_segment)->file_offset();
  uint64_t offset      = virtual_address - baseAddress;

  return offset;

}


bool Binary::has_interpreter(void) const {
  auto&& it_segment_interp = std::find_if(
      std::begin(this->segments_),
      std::end(this->segments_),
      [] (const Segment* segment)
      {
        return segment != nullptr and segment->type() == SEGMENT_TYPES::PT_INTERP;
      });

  return it_segment_interp != std::end(this->segments_) and not this->interpreter_.empty();
}

const std::string& Binary::interpreter(void) const {
  if (not this->has_interpreter()) {
    throw not_found("Interpreter not found!");
  }
  return this->interpreter_;
}

void Binary::interpreter(const std::string& interpreter) {
  this->interpreter_ = interpreter;
}


void Binary::write(const std::string& filename) {
  Builder builder{this};
  builder.build();
  builder.write(filename);
}


uint64_t Binary::entrypoint() const {
  return this->header().entrypoint();
}


const Section& Binary::section_from_offset(uint64_t offset) const {
  auto&& it_section = std::find_if(
      this->sections_.cbegin(),
      this->sections_.cend(),
      [&offset] (const Section* section) {
        if (section == nullptr) {
          return false;
        }
        return ((section->offset() <= offset) and
            (section->offset() + section->size()) > offset);
      });

  if (it_section == this->sections_.cend()) {
    throw not_found("Unable to find the section");
  }

  return **it_section;
}

Section& Binary::section_from_offset(uint64_t offset) {
  return const_cast<Section&>(static_cast<const Binary*>(this)->section_from_offset(offset));
}



const Section& Binary::section_from_virtual_address(uint64_t address) const {
  auto&& it_section = std::find_if(
      this->sections_.cbegin(),
      this->sections_.cend(),
      [&address] (const Section* section) {
        if (section == nullptr) {
          return false;
        }
        return ((section->virtual_address() <= address) and
            (section->virtual_address() + section->size()) > address);
      });

  if (it_section == this->sections_.cend()) {
    throw not_found("Unable to find the section");
  }

  return **it_section;
}

Section& Binary::section_from_virtual_address(uint64_t address) {
  return const_cast<Section&>(static_cast<const Binary*>(this)->section_from_virtual_address(address));
}

std::vector<uint8_t> Binary::get_content_from_virtual_address(uint64_t virtual_address, uint64_t size, LIEF::Binary::VA_TYPES) const {
  const Segment& segment = this->segment_from_virtual_address(virtual_address);

  const std::vector<uint8_t>& content = segment.content();
  const uint64_t offset = virtual_address - segment.virtual_address();
  uint64_t checked_size = size;
  if ((offset + checked_size) > content.size()) {
    checked_size = checked_size - (offset + checked_size - content.size());
  }

  return {content.data() + offset, content.data() + offset + checked_size};
}


const DynamicEntry& Binary::get(DYNAMIC_TAGS tag) const {

  if (not this->has(tag)) {
    throw not_found("Unable to find the dynamic entry with tag '" + std::string(to_string(tag)) + "'.");
  }

  auto&& it_entry = std::find_if(
      std::begin(this->dynamic_entries_),
      std::end(this->dynamic_entries_),
      [tag] (const DynamicEntry* entry)
      {
        return entry != nullptr and entry->tag() == tag;
      });

  return **it_entry;
}

DynamicEntry& Binary::get(DYNAMIC_TAGS tag) {
  return const_cast<DynamicEntry&>(static_cast<const Binary*>(this)->get(tag));
}


bool Binary::has(DYNAMIC_TAGS tag) const {
  auto&& it_entry = std::find_if(
      std::begin(this->dynamic_entries_),
      std::end(this->dynamic_entries_),
      [tag] (const DynamicEntry* entry)
      {
        return entry != nullptr and entry->tag() == tag;
      });

  return it_entry != std::end(this->dynamic_entries_);
}

const Segment& Binary::get(SEGMENT_TYPES type) const {

  if (not this->has(type)) {
    throw not_found("Unable to find a segment of type '" + std::string(to_string(type)) + "'.");
  }

  auto&& it_segment = std::find_if(
      std::begin(this->segments_),
      std::end(this->segments_),
      [type] (const Segment* segment)
      {
        return segment != nullptr and segment->type() == type;
      });

  return **it_segment;
}


Segment& Binary::get(SEGMENT_TYPES type) {
  return const_cast<Segment&>(static_cast<const Binary*>(this)->get(type));
}

const Note& Binary::get(NOTE_TYPES type) const {

  if (not this->has(type)) {
    throw not_found("Unable to find a note of type '" + std::string(to_string(type)) + "'.");
  }

  auto&& it_note = std::find_if(
      std::begin(this->notes_),
      std::end(this->notes_),
      [type] (const Note* note)
      {
        return static_cast<NOTE_TYPES>(note->type()) == type;
      });

  return **it_note;
}


Note& Binary::get(NOTE_TYPES type) {
  return const_cast<Note&>(static_cast<const Binary*>(this)->get(type));
}

const Section& Binary::get(ELF_SECTION_TYPES type) const {

  if (not this->has(type)) {
    throw not_found("Unable to find a section of type '" + std::string(to_string(type)) + "'.");
  }

  auto&& it_section = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [type] (const Section* section)
      {
        return section->type() == type;
      });

  return **it_section;
}


Section& Binary::get(ELF_SECTION_TYPES type) {
  return const_cast<Section&>(static_cast<const Binary*>(this)->get(type));
}



bool Binary::has(SEGMENT_TYPES type) const {
  auto&& it_segment = std::find_if(
      std::begin(this->segments_),
      std::end(this->segments_),
      [type] (const Segment* segment)
      {
        return segment != nullptr and segment->type() == type;
      });

  return it_segment != std::end(this->segments_);
}


bool Binary::has(NOTE_TYPES type) const {
  auto&& it_note = std::find_if(
      std::begin(this->notes_),
      std::end(this->notes_),
      [type] (const Note* note)
      {
        return static_cast<NOTE_TYPES>(note->type()) == type;
      });

  return it_note != std::end(this->notes_);
}

bool Binary::has(ELF_SECTION_TYPES type) const {
  auto&& it_section = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [type] (const Section* section)
      {
        return section->type() == type;
      });

  return it_section != std::end(this->sections_);
}



void Binary::permute_dynamic_symbols(const std::vector<size_t>& permutation) {
  std::set<size_t> done;
  for (size_t i = 0; i < permutation.size(); ++i) {
    if (permutation[i] == i or done.count(permutation[i]) > 0 or done.count(permutation[i]) > 0) {
      continue;
    }

    if (this->dynamic_symbols_[i]->has_version() and this->dynamic_symbols_[permutation[i]]->has_version()) {
      std::swap(this->symbol_version_table_[i], this->symbol_version_table_[permutation[i]]);
      std::swap(this->dynamic_symbols_[i], this->dynamic_symbols_[permutation[i]]);
      done.insert(permutation[i]);
      done.insert(i);
    } else if (not this->dynamic_symbols_[i]->has_version() and not this->dynamic_symbols_[permutation[i]]->has_version()) {
      std::swap(this->dynamic_symbols_[i], this->dynamic_symbols_[permutation[i]]);
      done.insert(permutation[i]);
      done.insert(i);
    } else {
      LOG(ERROR) << "Can't apply permutation at index " << std::dec << i;
    }

  }
}

LIEF::Header Binary::get_abstract_header(void) const {
  LIEF::Header header;
  const std::pair<ARCHITECTURES, std::set<MODES>>& am = this->header().abstract_architecture();
  header.architecture(am.first);
  header.modes(am.second);
  header.entrypoint(this->header().entrypoint());

  if (this->header().file_type() == E_TYPE::ET_DYN and this->has_interpreter()) { // PIE
    header.object_type(OBJECT_TYPES::TYPE_EXECUTABLE);
  } else {
    header.object_type(this->header().abstract_object_type());
  }

  header.endianness(this->header().abstract_endianness());

  return header;
}


bool Binary::has_notes(void) const {
  auto&& it_segment_note = std::find_if(
      std::begin(this->segments_),
      std::end(this->segments_),
      [] (const Segment* segment) {
        return segment != nullptr and segment->type() == SEGMENT_TYPES::PT_NOTE;
      });

  return it_segment_note != std::end(this->segments_) and this->notes().size() > 0;
}

it_const_notes Binary::notes(void) const {
  return this->notes_;
}

it_notes Binary::notes(void) {
  return this->notes_;
}


void Binary::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool Binary::use_gnu_hash(void) const {

  auto&& it_gnu_hash = std::find_if(
      std::begin(this->dynamic_entries_),
      std::end(this->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_GNU_HASH;
      });

  return it_gnu_hash != std::end(this->dynamic_entries_);
}


const GnuHash& Binary::gnu_hash(void) const {
  if (this->use_gnu_hash()) {
    return this->gnu_hash_;
  } else {
    throw not_found("GNU hash is not used!");
  }
}


bool Binary::use_sysv_hash(void) const {
  auto&& it_sysv_hash = std::find_if(
      std::begin(this->dynamic_entries_),
      std::end(this->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_HASH;
      });

  return it_sysv_hash != std::end(this->dynamic_entries_);
}

const SysvHash& Binary::sysv_hash(void) const {
  if (this->use_sysv_hash()) {
    return this->sysv_hash_;
  } else {
    throw not_found("SYSV hash is not used!");
  }
}


void Binary::shift_sections(uint64_t from, uint64_t shift) {
  VLOG(VDEBUG) << "Shift Sections";
  /// TODO: ADDRESS ?????????? ///////////
  for (Section* section : this->sections_) {
    VLOG(VDEBUG) << "[BEFORE] " << *section;
    if (section->file_offset() >= from) {
      section->file_offset(section->file_offset() + shift);
      if (section->virtual_address() > 0) {
        section->virtual_address(section->virtual_address() + shift);
      }
    }
    VLOG(VDEBUG) << "[AFTER] " << *section << std::endl;
  }

}

void Binary::shift_segments(uint64_t from, uint64_t shift) {

  VLOG(VDEBUG) << "Shift Segments";

  for (Segment* segment : this->segments_) {
    VLOG(VDEBUG) << "[BEFORE] " << *segment;
    if (segment->file_offset() >= from) {

      segment->file_offset(segment->file_offset() + shift);
      segment->virtual_address(segment->virtual_address() + shift);
      segment->physical_address(segment->physical_address() + shift);

    }
    VLOG(VDEBUG) << "[AFTER] " << *segment << std::endl;
  }
}

void Binary::shift_dynamic_entries(uint64_t from, uint64_t shift) {
  VLOG(VDEBUG) << "Shift Dynamic entries";

  for (DynamicEntry* entry : this->dynamic_entries_) {
    VLOG(VDEBUG) << "[BEFORE] " << *entry;
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
              if (
                  (this->type() == ELF_CLASS::ELFCLASS32 and static_cast<int32_t>(address) > 0) or
                  (this->type() == ELF_CLASS::ELFCLASS64 and static_cast<int64_t>(address) > 0)
                ) {
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
          VLOG(VDEBUG) << to_string(entry->tag()) << " not patched";
        }
    }
    VLOG(VDEBUG) << "[AFTER] " << *entry << std::endl;
  }
}


void Binary::shift_symbols(uint64_t from, uint64_t shift) {
  VLOG(VDEBUG) << "Shift Symbols";
  for (Symbol& symbol : this->symbols()) {
    VLOG(VDEBUG) << "[BEFORE] " << symbol;
    if (symbol.value() >= from) {
      symbol.value(symbol.value() + shift);
    }
    VLOG(VDEBUG) << "[AFTER] " << symbol << std::endl;
  }
}


void Binary::shift_relocations(uint64_t from, uint64_t shift) {
  const ARCH arch = this->header().machine_type();

  VLOG(VDEBUG) << "Shift relocations for architecture: " << to_string(arch);

  switch(arch) {
    case ARCH::EM_ARM:
      {
        this->patch_relocations<ARCH::EM_ARM>(from, shift);
        break;
      }

    case ARCH::EM_AARCH64:
      {
        this->patch_relocations<ARCH::EM_AARCH64>(from, shift);
        break;
      }

    case ARCH::EM_X86_64:
      {
        this->patch_relocations<ARCH::EM_X86_64>(from, shift);
        break;
      }

    case ARCH::EM_386:
      {
        this->patch_relocations<ARCH::EM_386>(from, shift);
        break;
      }

    case ARCH::EM_PPC:
      {
        this->patch_relocations<ARCH::EM_PPC>(from, shift);
        break;
      }

      /*
    case ARCH::EM_PPC64:
      {
        this->patch_relocations<ARCH::EM_PPC64>(from, shift);
        break;
      }
      */
      
    default:
      {
        LOG(WARNING) << "Relocations for architecture " << to_string(arch) << " is not supported!";
      }
  }
}


uint64_t Binary::last_offset_section(void) const {
  return std::accumulate(
      std::begin(this->sections_),
      std::end(this->sections_), 0llu,
      [] (uint64_t offset, const Section* section) {
        return std::max<uint64_t>(section->file_offset() + section->size(), offset);
      });
}


uint64_t Binary::last_offset_segment(void) const {
  return std::accumulate(
      std::begin(this->segments_),
      std::end(this->segments_), 0llu,
      [] (uint64_t offset, const Segment* segment) {
        return std::max<uint64_t>(segment->file_offset() + segment->physical_size(), offset);
      });
}


uint64_t Binary::next_virtual_address(void) const {

  uint64_t va = std::accumulate(
            std::begin(this->segments_),
            std::end(this->segments_), 0llu,
            [] (uint32_t address, const Segment* segment) {
              return std::max<uint64_t>(segment->virtual_address() + segment->virtual_size(), address);
            });

  if (this->type() == ELF_CLASS::ELFCLASS32) {
    va = round<uint32_t>(static_cast<uint32_t>(va));
  }

  if (this->type() == ELF_CLASS::ELFCLASS64) {
    va = round<uint64_t>(static_cast<uint64_t>(va));
  }

  return va;
}


DynamicEntryLibrary& Binary::add_library(const std::string& library_name) {
  return *dynamic_cast<DynamicEntryLibrary*>(&this->add(DynamicEntryLibrary{library_name}));
}


void Binary::remove_library(const std::string& library_name) {
  this->remove(this->get_library(library_name));
}


DynamicEntryLibrary& Binary::get_library(const std::string& library_name) {
  return const_cast<DynamicEntryLibrary&>(static_cast<const Binary*>(this)->get_library(library_name));
}

const DynamicEntryLibrary& Binary::get_library(const std::string& library_name) const {
  if (not this->has_library(library_name)) {
    throw not_found("Can't find library '" + library_name + "' !");
  }

  auto&& it_needed = std::find_if(
      std::begin(this->dynamic_entries_),
      std::end(this->dynamic_entries_),
      [&library_name] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_NEEDED and
               dynamic_cast<const DynamicEntryLibrary*>(entry)->name() == library_name;
      });
  return *dynamic_cast<const DynamicEntryLibrary*>(*it_needed);
}

bool Binary::has_library(const std::string& name) const {
  auto&& it_needed = std::find_if(
      std::begin(this->dynamic_entries_),
      std::end(this->dynamic_entries_),
      [&name] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_NEEDED and
               dynamic_cast<const DynamicEntryLibrary*>(entry)->name() == name;
      });
  return it_needed != std::end(this->dynamic_entries_);
}

// Operator+=
// ==========
Binary& Binary::operator+=(const DynamicEntry& entry) {
  this->add(entry);
  return *this;
}

Binary& Binary::operator+=(const Section& section) {
  this->add(section);
  return *this;
}

Binary& Binary::operator+=(const Segment& segment) {
  this->add(segment);
  return *this;
}

Binary& Binary::operator+=(const Note& note) {
  this->add(note);
  return *this;
}

// Operator -=
// ===========
Binary& Binary::operator-=(const DynamicEntry& entry) {
  this->remove(entry);
  return *this;
}

Binary& Binary::operator-=(DYNAMIC_TAGS tag) {
  this->remove(tag);
  return *this;
}


Binary& Binary::operator-=(const Note& note) {
  this->remove(note);
  return *this;
}

Binary& Binary::operator-=(NOTE_TYPES type) {
  this->remove(type);
  return *this;
}

// Operator[]
// ==========
Segment& Binary::operator[](SEGMENT_TYPES type) {
  return this->get(type);
}

const Segment& Binary::operator[](SEGMENT_TYPES type) const {
  return this->get(type);
}

DynamicEntry& Binary::operator[](DYNAMIC_TAGS tag) {
  return this->get(tag);
}

const DynamicEntry& Binary::operator[](DYNAMIC_TAGS tag) const {
  return this->get(tag);
}

Note& Binary::operator[](NOTE_TYPES type) {
  return this->get(type);
}

const Note& Binary::operator[](NOTE_TYPES type) const {
  return this->get(type);
}

Section& Binary::operator[](ELF_SECTION_TYPES type) {
  return this->get(type);
}

const Section& Binary::operator[](ELF_SECTION_TYPES type) const {
  return this->get(type);
}

bool Binary::operator==(const Binary& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Binary::operator!=(const Binary& rhs) const {
  return not (*this == rhs);
}

std::ostream& Binary::print(std::ostream& os) const {

  os << "Header" << std::endl;
  os << "======" << std::endl;

  os << this->header();
  os << std::endl;


  os << "Sections" << std::endl;
  os << "========" << std::endl;
  for (const Section& section : this->sections()) {
    os << section << std::endl;
  }
  os << std::endl;


  os << "Segments" << std::endl;
  os << "========" << std::endl;
  for (const Segment& segment : this->segments()) {
    os << segment << std::endl;
  }

  os << std::endl;


  os << "Dynamic entries" << std::endl;
  os << "===============" << std::endl;

  for (const DynamicEntry& entry : this->dynamic_entries()) {
    os << entry << std::endl;
  }

  os << std::endl;


  os << "Dynamic symbols" << std::endl;
  os << "===============" << std::endl;

  for (const Symbol& symbol : this->dynamic_symbols()) {
    os << symbol << std::endl;
  }

  os << std::endl;


  os << "Static symbols" << std::endl;
  os << "==============" << std::endl;

  for (const Symbol& symbol : this->static_symbols()) {
    os << symbol << std::endl;
  }

  os << std::endl;


  os << "Symbol versions" << std::endl;
  os << "===============" << std::endl;

  for (const SymbolVersion& sv : this->symbols_version()) {
    os << sv << std::endl;
  }

  os << std::endl;


  os << "Symbol versions definition" << std::endl;
  os << "==========================" << std::endl;

  for (const SymbolVersionDefinition& svd : this->symbols_version_definition()) {
    os << svd << std::endl;
  }

  os << std::endl;


  os << "Symbol version requirement" << std::endl;
  os << "==========================" << std::endl;

  for (const SymbolVersionRequirement& svr : this->symbols_version_requirement()) {
    os << svr << std::endl;
  }

  os << std::endl;


  os << "Dynamic relocations" << std::endl;
  os << "===================" << std::endl;

  for (const Relocation& relocation : this->dynamic_relocations()) {
    os << relocation << std::endl;
  }

  os << std::endl;


  os << ".plt.got relocations" << std::endl;
  os << "====================" << std::endl;

  for (const Relocation& relocation : this->pltgot_relocations()) {
    os << relocation << std::endl;
  }

  os << std::endl;

  if (this->notes().size() > 0) {
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
  if (this->use_gnu_hash()) {
    os << "GNU Hash Table" << std::endl;
    os << "==============" << std::endl;

    os << this->gnu_hash() << std::endl;

    os << std::endl;
  }


  if (this->use_sysv_hash()) {
    os << "SYSV Hash Table" << std::endl;
    os << "===============" << std::endl;

    os << this->sysv_hash() << std::endl;

    os << std::endl;
  }



  return os;
}



Binary::~Binary(void) {
  for (Relocation* relocation : this->relocations_) {
    delete relocation;
  }

  for (Section* section : this->sections_) {
    delete section;
  }

  for (Segment* segment : this->segments_) {
    delete segment;
  }

  for (DynamicEntry* entry : this->dynamic_entries_) {
    delete entry;
  }

  for (Symbol* symbol : this->dynamic_symbols_) {
    delete symbol;
  }

  for (Symbol* symbol : this->static_symbols_) {
    delete symbol;
  }

  for (SymbolVersion* symbol_version : this->symbol_version_table_) {
    delete symbol_version;
  }

  for (SymbolVersionDefinition* svd : this->symbol_version_definition_) {
    delete svd;
  }

  for (SymbolVersionRequirement* svr : this->symbol_version_requirements_) {
    delete svr;
  }

  for (Note* note : this->notes_) {
    delete note;
  }

  delete datahandler_;
}


}
}
