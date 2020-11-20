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
#include <cctype>
#include "logging.hpp"

#include "LIEF/utils.hpp"
#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/Parser.hpp"
#include "LIEF/ELF/DynamicEntryFlags.hpp"
#include "LIEF/ELF/Relocation.hpp"
#include "LIEF/ELF/Segment.hpp"
#include "LIEF/ELF/Section.hpp"
#include "LIEF/ELF/DynamicEntryLibrary.hpp"
#include "LIEF/ELF/DynamicEntryArray.hpp"
#include "LIEF/ELF/DynamicSharedObject.hpp"
#include "LIEF/ELF/DynamicEntryRunPath.hpp"
#include "LIEF/ELF/DynamicEntryRpath.hpp"
#include "LIEF/ELF/SymbolVersionRequirement.hpp"
#include "LIEF/ELF/SymbolVersionDefinition.hpp"
#include "LIEF/ELF/SymbolVersionAuxRequirement.hpp"
#include "LIEF/ELF/SymbolVersionAux.hpp"
#include "LIEF/ELF/Symbol.hpp"
#include "LIEF/ELF/SymbolVersion.hpp"
#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/DataHandler/Handler.hpp"


#include "Object.tcc"

namespace LIEF {
namespace ELF {
template<typename ELF_T>
void Parser::parse_binary(void) {
  using Elf_Off  = typename ELF_T::Elf_Off;

  LIEF_DEBUG("Start parsing");
  // Parse header
  // ============
  if (not this->parse_header<ELF_T>()) {
    return;
  }

  // Parse Sections
  // ==============
  try {
    if (this->binary_->header_.section_headers_offset() > 0) {
      this->parse_sections<ELF_T>();
    } else {
      LIEF_WARN("The current binary doesn't have a section header");
    }

  } catch (const LIEF::read_out_of_bound& e) {
    LIEF_WARN(e.what());
  } catch (const corrupted& e) {
    LIEF_WARN(e.what());
  }


  // Parse segments
  // ==============

  try {
    if (this->binary_->header_.program_headers_offset() > 0) {
      LIEF_SW_START(sw);
      this->parse_segments<ELF_T>();
      LIEF_SW_END("segments parsed in {}", duration_cast<std::chrono::microseconds>(sw.elapsed()));
    } else {
      LIEF_WARN("Binary doesn't have a program header");
    }
  } catch (const corrupted& e) {
    LIEF_WARN(e.what());
  }

  // Parse Dynamic elements
  // ======================

  // Find the dynamic Segment
  auto&& it_segment_dynamic = std::find_if(
      std::begin(this->binary_->segments_),
      std::end(this->binary_->segments_),
      [] (const Segment* segment) {
        return segment != nullptr and segment->type() == SEGMENT_TYPES::PT_DYNAMIC;
      });

  if (it_segment_dynamic != std::end(this->binary_->segments_)) {

    const Elf_Off offset = (*it_segment_dynamic)->file_offset();
    const Elf_Off size   = (*it_segment_dynamic)->physical_size();

    try {
      this->parse_dynamic_entries<ELF_T>(offset, size);
    } catch (const exception& e) {
      LIEF_WARN(e.what());
    }
  }


  // Parse dynamic symbols
  // =====================
  auto&& it_dynamic_symbol_table = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_SYMTAB;
      });

  auto&& it_dynamic_symbol_size = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_SYMENT;
      });

  if (it_dynamic_symbol_table != std::end(this->binary_->dynamic_entries_) and
      it_dynamic_symbol_size != std::end(this->binary_->dynamic_entries_)) {
    const uint64_t virtual_address = (*it_dynamic_symbol_table)->value();
    //const uint64_t size            = (*it_dynamic_symbol_size)->value();
    try {
      const uint64_t offset = this->binary_->virtual_address_to_offset(virtual_address);
      this->parse_dynamic_symbols<ELF_T>(offset);
    } catch (const LIEF::exception& e) {
      LIEF_ERR(e.what());
    }
  }

  // Parse dynamic relocations
  // =========================

  // RELA
  // ----
  auto&& it_dynamic_relocations = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_RELA;
      });

  auto&& it_dynamic_relocations_size = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_RELASZ;
      });

  if (it_dynamic_relocations != std::end(this->binary_->dynamic_entries_) and
      it_dynamic_relocations_size != std::end(this->binary_->dynamic_entries_)) {
    const uint64_t virtual_address = (*it_dynamic_relocations)->value();
    const uint64_t size            = (*it_dynamic_relocations_size)->value();
    try {
      uint64_t offset = this->binary_->virtual_address_to_offset(virtual_address);
      this->parse_dynamic_relocations<ELF_T, typename ELF_T::Elf_Rela>(offset, size);
    } catch (const LIEF::exception& e) {
      LIEF_WARN(e.what());
    }
  }


  // REL
  // ---
  it_dynamic_relocations = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_REL;
      });

  it_dynamic_relocations_size = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_RELSZ;
      });

  if (it_dynamic_relocations != std::end(this->binary_->dynamic_entries_) and
      it_dynamic_relocations_size != std::end(this->binary_->dynamic_entries_)) {
    const uint64_t virtual_address = (*it_dynamic_relocations)->value();
    const uint64_t size            = (*it_dynamic_relocations_size)->value();
    try {
      const uint64_t offset = this->binary_->virtual_address_to_offset(virtual_address);
      this->parse_dynamic_relocations<ELF_T, typename ELF_T::Elf_Rel>(offset, size);
    } catch (const LIEF::exception& e) {
      LIEF_WARN(e.what());
    }

  }

  // Parse PLT/GOT Relocations
  // ==========================
  auto&& it_pltgot_relocations = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_JMPREL;
      });

  auto&& it_pltgot_relocations_size = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_PLTRELSZ;
      });

  auto&& it_pltgot_relocations_type = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_PLTREL;
      });

  if (it_pltgot_relocations != std::end(this->binary_->dynamic_entries_) and
      it_pltgot_relocations_size != std::end(this->binary_->dynamic_entries_)) {
    const uint64_t virtual_address = (*it_pltgot_relocations)->value();
    const uint64_t size            = (*it_pltgot_relocations_size)->value();
    DYNAMIC_TAGS type;
    if (it_pltgot_relocations_type != std::end(this->binary_->dynamic_entries_)) {
      type = static_cast<DYNAMIC_TAGS>((*it_pltgot_relocations_type)->value());
    } else {
      // Try to guess: We assume that on ELF64 -> DT_RELA and on ELF32 -> DT_REL
      if (std::is_same<ELF_T, ELF64>::value) {
        type = DYNAMIC_TAGS::DT_RELA;
      } else {
        type = DYNAMIC_TAGS::DT_REL;
      }
    }

    try {
      const uint64_t offset = this->binary_->virtual_address_to_offset(virtual_address);
      if (type == DYNAMIC_TAGS::DT_RELA) {
        this->parse_pltgot_relocations<ELF_T, typename ELF_T::Elf_Rela>(offset, size);
      } else {
        this->parse_pltgot_relocations<ELF_T, typename ELF_T::Elf_Rel>(offset, size);
      }
    } catch (const LIEF::exception& e) {
      LIEF_WARN(e.what());

    }


  }

  // Parse Symbol Version
  // ====================
  auto&& it_symbol_versions = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_VERSYM;
      });

  if (it_symbol_versions != std::end(this->binary_->dynamic_entries_)) {
    const uint64_t virtual_address = (*it_symbol_versions)->value();
    try {
      uint64_t offset = this->binary_->virtual_address_to_offset(virtual_address);
      this->parse_symbol_version(offset);
    } catch (const LIEF::exception&) {

    }

  }

  // Parse Symbol Version Requirement
  // ================================
  auto&& it_symbol_version_requirement = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_VERNEED;
      });

  auto&& it_symbol_version_requirement_size = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_VERNEEDNUM;
      });

  if (it_symbol_version_requirement != std::end(this->binary_->dynamic_entries_) and
      it_symbol_version_requirement_size != std::end(this->binary_->dynamic_entries_)) {

    const DynamicEntry* dt_verneed     = *it_symbol_version_requirement;
    const DynamicEntry* dt_verneed_num = *it_symbol_version_requirement_size;

    const uint64_t virtual_address = dt_verneed->value();
    const uint32_t nb_entries = std::min(Parser::NB_MAX_SYMBOLS, static_cast<uint32_t>(dt_verneed_num->value()));
    try {
      const uint64_t offset = this->binary_->virtual_address_to_offset(virtual_address);
      this->parse_symbol_version_requirement<ELF_T>(offset, nb_entries);
    } catch (const LIEF::exception& e) {
      LIEF_WARN("{}", e.what());
    }

  }

  // Parse Symbol Version Definition
  // ===============================
  auto&& it_symbol_version_definition = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_VERDEF;
      });

  auto&& it_symbol_version_definition_size = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_VERDEFNUM;
      });

  if (it_symbol_version_definition != std::end(this->binary_->dynamic_entries_) and
      it_symbol_version_definition_size != std::end(this->binary_->dynamic_entries_)) {
    const uint64_t virtual_address = (*it_symbol_version_definition)->value();
    const uint32_t size            = static_cast<uint32_t>((*it_symbol_version_definition_size)->value());
    try {
      const uint64_t offset = this->binary_->virtual_address_to_offset(virtual_address);
      this->parse_symbol_version_definition<ELF_T>(offset, size);
    } catch (const LIEF::exception&) {

    }

  }


  // Parse static symbols
  // ====================
  auto&& it_symtab_section = std::find_if(
      std::begin(this->binary_->sections_),
      std::end(this->binary_->sections_),
      [] (const Section* section)
      {
        return section != nullptr and section->type() == ELF_SECTION_TYPES::SHT_SYMTAB;
      });

  if (it_symtab_section != std::end(this->binary_->sections_)) {
    const Section* section = *it_symtab_section;
    uint32_t nb_entries = static_cast<uint32_t>((section->size() / sizeof(typename ELF_T::Elf_Sym)));

    if (section->link() == 0 or section->link() >= this->binary_->sections_.size()) {
      LIEF_WARN("section->link() is not valid !");
    } else {
      // We should have:
      // nb_entries == section->information())
      // but lots of compiler not respect this rule
      this->parse_static_symbols<ELF_T>(
          section->file_offset(),
          nb_entries,
          this->binary_->sections_[section->link()]);
    }

    it_symtab_section = std::find_if(
        it_symtab_section + 1,
        std::end(this->binary_->sections_),
        [] (const Section* section)
        {
        return section != nullptr and section->type() == ELF_SECTION_TYPES::SHT_SYMTAB;
        });

    if (it_symtab_section != std::end(this->binary_->sections_)) {
      LIEF_WARN("Support for multiple SHT_SYMTAB section is not implemented");
    }
  }


  // Parse Symbols's hash
  // ====================

  auto&& it_symbol_hash = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_HASH;
      });

  auto&& it_symbol_gnu_hash = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_GNU_HASH;
      });

  if (it_symbol_hash != std::end(this->binary_->dynamic_entries_)) {
    try {
      const uint64_t symbol_sys_hash_offset = this->binary_->virtual_address_to_offset((*it_symbol_hash)->value());
      this->parse_symbol_sysv_hash(symbol_sys_hash_offset);
    } catch (const conversion_error&) {
    } catch (const exception& e) {
      LIEF_WARN("{}", e.what());
    }
  }


  if (it_symbol_gnu_hash != std::end(this->binary_->dynamic_entries_)) {
    try {
      const uint64_t symbol_gnu_hash_offset = this->binary_->virtual_address_to_offset((*it_symbol_gnu_hash)->value());
      this->parse_symbol_gnu_hash<ELF_T>(symbol_gnu_hash_offset);
    } catch (const conversion_error&) {
    } catch (const exception& e) {
      LIEF_WARN("{}", e.what());
    }
  }

  // Parse Note segment
  // ==================
  auto&& it_segment_note = std::find_if(
      std::begin(this->binary_->segments_),
      std::end(this->binary_->segments_),
      [] (const Segment* segment) {
        return segment != nullptr and segment->type() == SEGMENT_TYPES::PT_NOTE;
      });

  if (it_segment_note != std::end(this->binary_->segments_)) {
    try {
      const uint64_t note_offset = this->binary_->virtual_address_to_offset((*it_segment_note)->virtual_address());
      this->parse_notes(note_offset, (*it_segment_note)->physical_size());
    } catch (const conversion_error&) {
    } catch (const exception& e) {
      LIEF_WARN("{}", e.what());
    }
  }

  // Parse Note Sections
  // ===================
  for (const Section& section : this->binary_->sections()) {
    if (section.type() != ELF_SECTION_TYPES::SHT_NOTE) {
      continue;
    }

    try {
      this->parse_notes(section.offset(), section.size());
    } catch (const conversion_error&) {
    } catch (const exception& e) {
      LIEF_WARN("{}", e.what());
    }


  }

  // Try to parse using sections
  // If we don't have any relocations, we parse all relocation sections
  // otherwise, only the non-allocated sections to avoid parsing dynamic
  // relocations (or plt relocations) twice.
  bool skip_allocated_sections = this->binary_->relocations_.size() > 0;
  for (const Section& section : this->binary_->sections()) {
    if(skip_allocated_sections && section.has(ELF_SECTION_FLAGS::SHF_ALLOC)){
      continue;
    }
    try {
      if (section.type() == ELF_SECTION_TYPES::SHT_REL) {
        this->parse_section_relocations<ELF_T, typename ELF_T::Elf_Rel>(section);
      }
      else if (section.type() == ELF_SECTION_TYPES::SHT_RELA) {
        this->parse_section_relocations<ELF_T, typename ELF_T::Elf_Rela>(section);
      }

    } catch (const exception& e) {
      LIEF_WARN("Unable to parse relocations from section '{}' ({})", section.name(), e.what());
    }
  }

  this->link_symbol_version();
  this->parse_overlay();
}


template<typename ELF_T>
bool Parser::parse_header(void) {
  using Elf_Ehdr = typename ELF_T::Elf_Ehdr;

  LIEF_DEBUG("[+] Parsing Header");
  this->stream_->setpos(0);
  if (this->stream_->can_read<Elf_Ehdr>()) {
    Elf_Ehdr hdr = this->stream_->read_conv<Elf_Ehdr>();
    this->binary_->header_ = &hdr;
    return true;
  } else {
    LIEF_ERR("Can't read header!");
    return false;
  }
}


template<typename ELF_T>
uint32_t Parser::get_numberof_dynamic_symbols(DYNSYM_COUNT_METHODS mtd) const {

  switch(mtd) {
    case DYNSYM_COUNT_METHODS::COUNT_HASH:
      {
        return this->nb_dynsym_hash<ELF_T>();
        break;
      }

    case DYNSYM_COUNT_METHODS::COUNT_SECTION:
      {
        return this->nb_dynsym_section<ELF_T>();
        break;
      }


    case DYNSYM_COUNT_METHODS::COUNT_RELOCATIONS:
      {
        return this->nb_dynsym_relocations<ELF_T>();
        break;
      }

    case DYNSYM_COUNT_METHODS::COUNT_AUTO:
    default:
      {
        uint32_t nb_dynsym, nb_dynsym_tmp = 0;

        nb_dynsym = this->get_numberof_dynamic_symbols<ELF_T>(DYNSYM_COUNT_METHODS::COUNT_RELOCATIONS);

        nb_dynsym_tmp = this->get_numberof_dynamic_symbols<ELF_T>(DYNSYM_COUNT_METHODS::COUNT_SECTION);

        if (nb_dynsym_tmp < Parser::NB_MAX_SYMBOLS and
            nb_dynsym_tmp > nb_dynsym and
            (nb_dynsym_tmp - nb_dynsym) < Parser::DELTA_NB_SYMBOLS) {
          nb_dynsym = nb_dynsym_tmp;
        }

        nb_dynsym_tmp = this->get_numberof_dynamic_symbols<ELF_T>(DYNSYM_COUNT_METHODS::COUNT_HASH);

        if (nb_dynsym_tmp < Parser::NB_MAX_SYMBOLS and
            nb_dynsym_tmp > nb_dynsym and
            (nb_dynsym_tmp - nb_dynsym) < Parser::DELTA_NB_SYMBOLS) {
          nb_dynsym = nb_dynsym_tmp;
        }

        return nb_dynsym;
      }
  }
}

template<typename ELF_T>
uint32_t Parser::nb_dynsym_relocations(void) const {
  uint32_t nb_symbols = 0;

  // Dynamic Relocations
  // ===================

  // RELA
  // ----
  auto&& it_dynamic_relocations = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_RELA;
      });

  auto&& it_dynamic_relocations_size = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_RELASZ;
      });

  if (it_dynamic_relocations != std::end(this->binary_->dynamic_entries_) and
      it_dynamic_relocations_size != std::end(this->binary_->dynamic_entries_)) {
    const uint64_t virtual_address = (*it_dynamic_relocations)->value();
    const uint64_t size            = (*it_dynamic_relocations_size)->value();
    try {
      uint64_t offset = this->binary_->virtual_address_to_offset(virtual_address);
      nb_symbols = std::max(nb_symbols, this->max_relocation_index<ELF_T, typename ELF_T::Elf_Rela>(offset, size));
    } catch (const LIEF::exception&) {
    }
  }


  // REL
  // ---
  it_dynamic_relocations = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_REL;
      });

  it_dynamic_relocations_size = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_RELSZ;
      });

  if (it_dynamic_relocations != std::end(this->binary_->dynamic_entries_) and
      it_dynamic_relocations_size != std::end(this->binary_->dynamic_entries_)) {
    const uint64_t virtual_address = (*it_dynamic_relocations)->value();
    const uint64_t size            = (*it_dynamic_relocations_size)->value();
    try {
      const uint64_t offset = this->binary_->virtual_address_to_offset(virtual_address);
      nb_symbols = std::max(nb_symbols, this->max_relocation_index<ELF_T, typename ELF_T::Elf_Rel>(offset, size));
    } catch (const LIEF::exception&) {

    }

  }

  // Parse PLT/GOT Relocations
  // ==========================
  auto&& it_pltgot_relocations = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_JMPREL;
      });

  auto&& it_pltgot_relocations_size = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_PLTRELSZ;
      });

  auto&& it_pltgot_relocations_type = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_PLTREL;
      });

  if (it_pltgot_relocations != std::end(this->binary_->dynamic_entries_) and
      it_pltgot_relocations_size != std::end(this->binary_->dynamic_entries_)) {
    const uint64_t virtual_address = (*it_pltgot_relocations)->value();
    const uint64_t size            = (*it_pltgot_relocations_size)->value();
    DYNAMIC_TAGS type;
    if (it_pltgot_relocations_type != std::end(this->binary_->dynamic_entries_)) {
      type = static_cast<DYNAMIC_TAGS>((*it_pltgot_relocations_type)->value());
    } else {
      // Try to guess: We assume that on ELF64 -> DT_RELA and on ELF32 -> DT_REL
      if (std::is_same<ELF_T, ELF64>::value) {
        type = DYNAMIC_TAGS::DT_RELA;
      } else {
        type = DYNAMIC_TAGS::DT_REL;
      }
    }

    try {
      const uint64_t offset = this->binary_->virtual_address_to_offset(virtual_address);
      if (type == DYNAMIC_TAGS::DT_RELA) {
        nb_symbols = std::max(nb_symbols, this->max_relocation_index<ELF_T, typename ELF_T::Elf_Rela>(offset, size));
      } else {
        nb_symbols = std::max(nb_symbols, this->max_relocation_index<ELF_T, typename ELF_T::Elf_Rel>(offset, size));
      }
    } catch (const LIEF::exception& e) {
      LIEF_WARN("{}", e.what());
    }
  }

  return nb_symbols;
}

template<typename ELF_T, typename REL_T>
uint32_t Parser::max_relocation_index(uint64_t relocations_offset, uint64_t size) const {
  static_assert(std::is_same<REL_T, typename ELF_T::Elf_Rel>::value or
                std::is_same<REL_T, typename ELF_T::Elf_Rela>::value, "REL_T must be Elf_Rel or Elf_Rela");

  const uint8_t shift = std::is_same<ELF_T, ELF32>::value ? 8 : 32;

  const uint32_t nb_entries = static_cast<uint32_t>(size / sizeof(REL_T));

  uint32_t idx = 0;
  this->stream_->setpos(relocations_offset);
  for (uint32_t i = 0; i < nb_entries; ++i) {
    if (not this->stream_->can_read<REL_T>()) {
      break;
    }
    const REL_T reloc_entry = this->stream_->read_conv<REL_T>();
    idx = std::max(idx, static_cast<uint32_t>(reloc_entry.r_info >> shift));
  }
  return (idx + 1);
} // max_relocation_index



template<typename ELF_T>
uint32_t Parser::nb_dynsym_section(void) const {
  using Elf_Sym = typename ELF_T::Elf_Sym;
  using Elf_Off = typename ELF_T::Elf_Off;

  auto&& it_dynamic_section = std::find_if(
      std::begin(this->binary_->sections_),
      std::end(this->binary_->sections_),
      [] (const Section* section)
      {
        return section != nullptr and section->type() == ELF_SECTION_TYPES::SHT_DYNSYM;
      });

  if (it_dynamic_section == std::end(this->binary_->sections_)) {
    return 0;
  }

  const Elf_Off section_size = (*it_dynamic_section)->size();
  const uint32_t nb_symbols = static_cast<uint32_t>((section_size / sizeof(Elf_Sym)));
  return nb_symbols;
}

template<typename ELF_T>
uint32_t Parser::nb_dynsym_hash(void) const {

  if (this->binary_->has(DYNAMIC_TAGS::DT_HASH)) {
    return this->nb_dynsym_sysv_hash<ELF_T>();
  }

  if (this->binary_->has(DYNAMIC_TAGS::DT_GNU_HASH)) {
    return this->nb_dynsym_gnu_hash<ELF_T>();
  }

  return 0;
}


template<typename ELF_T>
uint32_t Parser::nb_dynsym_sysv_hash(void) const {
  using Elf_Off  = typename ELF_T::Elf_Off;

  const DynamicEntry& dyn_hash = this->binary_->get(DYNAMIC_TAGS::DT_HASH);
  const Elf_Off sysv_hash_offset = this->binary_->virtual_address_to_offset(dyn_hash.value());

  // From the doc: 'so nchain should equal the number of symbol table entries.'

  this->stream_->setpos(sysv_hash_offset + sizeof(uint32_t));
  if (this->stream_->can_read<uint32_t>()) {
    const size_t nb_symbols = this->stream_->read_conv<uint32_t>();
    return nb_symbols;
  }

  return 0;
}

template<typename ELF_T>
uint32_t Parser::nb_dynsym_gnu_hash(void) const {
  using uint__ = typename ELF_T::uint;
  using Elf_Off  = typename ELF_T::Elf_Off;

  const DynamicEntry& dyn_hash = this->binary_->get(DYNAMIC_TAGS::DT_GNU_HASH);
  const Elf_Off sysv_hash_offset = this->binary_->virtual_address_to_offset(dyn_hash.value());


  this->stream_->setpos(sysv_hash_offset);
  if (not this->stream_->can_read<uint32_t>()) {
    return 0;
  }

  const uint32_t nbuckets  = std::min(this->stream_->read_conv<uint32_t>(), Parser::NB_MAX_BUCKETS);

  if (not this->stream_->can_read<uint32_t>()) {
    return 0;
  }

  const uint32_t symndx    = this->stream_->read_conv<uint32_t>();

  if (not this->stream_->can_read<uint32_t>()) {
    return 0;
  }

  const uint32_t maskwords = std::min(this->stream_->read_conv<uint32_t>(), Parser::NB_MAX_MASKWORD);

  if (not this->stream_->can_read<uint32_t>()) {
    return 0;
  }

  const uint32_t shift2    = this->stream_->read_conv<uint32_t>();

  if (maskwords & (maskwords - 1)) {
    LIEF_WARN("maskwords is not a power of 2");
    return 0;
  }

  std::vector<uint64_t> bloom_filters;

  if (maskwords > Parser::NB_MAX_MASKWORD) {
    return 0;
  }

  bloom_filters.resize(maskwords);

  for (size_t i = 0; i < maskwords; ++i) {
    if (not this->stream_->can_read<uint__>()) {
      return 0;
    }

    bloom_filters[i] = this->stream_->read_conv<uint__>();
  }

  std::vector<uint32_t> buckets;
  if (nbuckets > Parser::NB_MAX_BUCKETS) {
    return 0;
  }

  buckets.reserve(nbuckets);
  for (size_t i = 0; i < nbuckets; ++i) {

    if (not this->stream_->can_read<uint32_t>()) {
      return 0;
    }

    buckets.push_back(this->stream_->read_conv<uint32_t>());
  }

  if (buckets.size() == 0) {
    return 0;
  }

  uint32_t nb_symbols = *std::max_element(std::begin(buckets), std::end(buckets));

  if (nb_symbols == 0) {
    return 0;
  }

  nb_symbols = symndx;

  GnuHash gnuhash{symndx, shift2, bloom_filters, buckets};
  gnuhash.c_ = sizeof(uint__) * 8;


  // Register the size of symbols store a the buckets
  std::vector<size_t> nbsym_buckets(nbuckets, 0);

  for (size_t i = 0; i < nbuckets; ++i) {
    uint32_t hash_value = 0;
    size_t nsyms = 0;
    do {
      if (not this->stream_->can_read<uint32_t>()) {
        return 0;
      }
      hash_value = this->stream_->read_conv<uint32_t>();

      nsyms++;
    } while ((hash_value & 1) == 0); // "It is set to 1 when a symbol is the last symbol in a given hash bucket"

    nbsym_buckets[i] = buckets[i] + nsyms;
  }

  nb_symbols = std::max<uint32_t>(nb_symbols, *std::max_element(std::begin(nbsym_buckets), std::end(nbsym_buckets)));
  return nb_symbols;
}

template<typename ELF_T>
void Parser::parse_sections(void) {
  using Elf_Shdr = typename ELF_T::Elf_Shdr;

  using Elf_Off  = typename ELF_T::Elf_Off;
  LIEF_DEBUG("Parsing Section");

  const Elf_Off shdr_offset = this->binary_->header_.section_headers_offset();
  const uint32_t numberof_sections = std::min<uint32_t>(this->binary_->header_.numberof_sections(), Parser::NB_MAX_SECTION);

  this->stream_->setpos(shdr_offset);

  for (size_t i = 0; i < numberof_sections; ++i) {
    LIEF_DEBUG("    Section #{:02d}", i);
    if (not this->stream_->can_read<Elf_Shdr>()) {
      LIEF_ERR("  Can't parse section #{:02d}", i);
      break;
    }

    const Elf_Shdr shdr = this->stream_->read_conv<Elf_Shdr>();

    std::unique_ptr<Section> section{new Section{&shdr}};
    section->datahandler_ = this->binary_->datahandler_;

    uint64_t section_end = section->file_offset();
    section_end += section->size();

    if (section_end > this->stream_->size() + 200_MB) {
      LIEF_ERR("  Section #{:d} is too large!", i);
      continue;
    }

    this->binary_->datahandler_->create(section->file_offset(), section->size(), DataHandler::Node::SECTION);

    // Only if it contains data (with bits)
    if (section->size() > 0 and section->size() < Parser::MAX_SECTION_SIZE) {

      const Elf_Off offset_to_content   = section->file_offset();
      const Elf_Off size                = section->size();
      this->binary_->datahandler_->reserve(section->file_offset(), section->size());

      const uint8_t* content = this->stream_->peek_array<uint8_t>(offset_to_content, size, /* check */false);
      if (content == nullptr) {
        LIEF_ERR("  Unable to get content of section #{:d}", i);
      } else {
        section->content({content, content + size});
      }
    }
    this->binary_->sections_.push_back(section.release());
  }

  LIEF_DEBUG("    Parse section names");
  // Parse name
  if (this->binary_->header_.section_name_table_idx() < this->binary_->sections_.size()) {
    const size_t section_string_index = this->binary_->header_.section_name_table_idx();
    const Section* string_section = this->binary_->sections_[section_string_index];
    for (Section* section : this->binary_->sections_) {
      std::string name = this->stream_->peek_string_at(string_section->file_offset() + section->name_idx());
      section->name(name);
    }
  } else {
    LIEF_WARN("Unable to fetch the string section");
  }
}

template<typename ELF_T>
void Parser::parse_segments(void) {
  using Elf_Phdr = typename ELF_T::Elf_Phdr;
  using Elf_Off  = typename ELF_T::Elf_Off;

  static const auto check_section_in_segment =
    [] (const Section* section, const Segment* segment) {
      if (section->virtual_address() > 0) {
        return section->virtual_address() >= segment->virtual_address() and
          (section->virtual_address() + section->size()) <=
          (segment->virtual_address() + segment->virtual_size());
      } else if (section->file_offset() > 0) {
        return section->file_offset() >= segment->file_offset() and
          (section->file_offset() + section->size()) < (segment->file_offset() + segment->physical_size());
      }
      return false;
    };

  LIEF_DEBUG("== Parse Segments ==");
  const Elf_Off segment_headers_offset = this->binary_->header().program_headers_offset();
  const uint32_t nbof_segments         = std::min<uint32_t>(this->binary_->header().numberof_segments(), Parser::NB_MAX_SEGMENTS);

  this->stream_->setpos(segment_headers_offset);

  for (size_t i = 0; i < nbof_segments; ++i) {
    if (not this->stream_->can_read<Elf_Phdr>()) {
      LIEF_ERR("Can't parse segement #{:d}", i);
      break;
    }
    const Elf_Phdr segment_headers = this->stream_->read_conv<Elf_Phdr>();

    std::unique_ptr<Segment> segment{new Segment{&segment_headers}};
    segment->datahandler_ = this->binary_->datahandler_;

    this->binary_->datahandler_->create(segment->file_offset(), segment->physical_size(), DataHandler::Node::SEGMENT);

    if (segment->physical_size() > 0 and segment->physical_size() < Parser::MAX_SEGMENT_SIZE) {

      const Elf_Off offset_to_content   = segment->file_offset();
      const Elf_Off size                = segment->physical_size();
      this->binary_->datahandler_->reserve(segment->file_offset(), segment->physical_size());
      const uint8_t* content = this->stream_->peek_array<uint8_t>(offset_to_content, size, /* check */false);
      if (content != nullptr) {
        segment->content({content, content + size});
        if (segment->type() == SEGMENT_TYPES::PT_INTERP) {
          this->binary_->interpreter_ = this->stream_->peek_string_at(offset_to_content, segment->physical_size());
        }
      } else {
        LIEF_ERR("Unable to get content of segment #{:d}", i);
      }
    }

    for (Section* section : this->binary_->sections_) {
      if (check_section_in_segment(section, segment.get())) {
        section->segments_.push_back(segment.get());
        segment->sections_.push_back(section);
      }
    }
    this->binary_->segments_.push_back(segment.release());
  }

}



template<typename ELF_T, typename REL_T>
void Parser::parse_dynamic_relocations(uint64_t relocations_offset, uint64_t size) {
  static_assert(std::is_same<REL_T, typename ELF_T::Elf_Rel>::value or
                std::is_same<REL_T, typename ELF_T::Elf_Rela>::value, "REL_T must be Elf_Rel or Elf_Rela");
  LIEF_DEBUG("== Parsing dynamic relocations ==");

  // Already parsed
  if (this->binary_->dynamic_relocations().size() > 0) {
    return;
  }

  const uint8_t shift = std::is_same<ELF_T, ELF32>::value ? 8 : 32;

  uint32_t nb_entries = static_cast<uint32_t>(size / sizeof(REL_T));

  nb_entries = std::min<uint32_t>(nb_entries, Parser::NB_MAX_RELOCATIONS);

  this->stream_->setpos(relocations_offset);
  for (uint32_t i = 0; i < nb_entries; ++i) {
    if (not this->stream_->can_read<REL_T>()) {
      break;
    }
    const REL_T raw_reloc = this->stream_->read_conv<REL_T>();
    std::unique_ptr<Relocation> reloc{new Relocation{&raw_reloc}};
    reloc->purpose(RELOCATION_PURPOSES::RELOC_PURPOSE_DYNAMIC);
    reloc->architecture_ = this->binary_->header().machine_type();

    const uint32_t idx =  static_cast<uint32_t>(raw_reloc.r_info >> shift);

    if (idx < this->binary_->dynamic_symbols_.size()) {
      reloc->symbol_ = this->binary_->dynamic_symbols_[idx];
    } else {
      LIEF_WARN("Unable to find the symbol associated with the relocation (idx: {}) {}", idx, *reloc);
    }

    this->binary_->relocations_.push_back(reloc.release());
  }
} // build_dynamic_reclocations



template<typename ELF_T>
void Parser::parse_static_symbols(uint64_t offset, uint32_t nbSymbols, const Section* string_section) {

  using Elf_Sym = typename ELF_T::Elf_Sym;
  LIEF_DEBUG("== Parsing static symbols ==");

  this->stream_->setpos(offset);
  for (uint32_t i = 0; i < nbSymbols; ++i) {
    if (not this->stream_->can_read<Elf_Sym>()) {
      break;
    }
    const Elf_Sym raw_sym = this->stream_->read_conv<Elf_Sym>();

    std::unique_ptr<Symbol> symbol{new Symbol{&raw_sym}};
    std::string symbol_name = this->stream_->peek_string_at(string_section->file_offset() + raw_sym.st_name);
    symbol->name(symbol_name);
    this->binary_->static_symbols_.push_back(symbol.release());
  }
} // build_static_symbols


template<typename ELF_T>
void Parser::parse_dynamic_symbols(uint64_t offset) {
  using Elf_Sym = typename ELF_T::Elf_Sym;
  using Elf_Off = typename ELF_T::Elf_Off;

  LIEF_DEBUG("== Parsing dynamics symbols ==");

  uint32_t nb_symbols = this->get_numberof_dynamic_symbols<ELF_T>(this->count_mtd_);

  const Elf_Off dynamic_symbols_offset = offset;
  const Elf_Off string_offset          = this->get_dynamic_string_table();

  LIEF_DEBUG("    - Number of symbols counted: {:d}", nb_symbols);
  LIEF_DEBUG("    - Table Offset: 0x{:x}", dynamic_symbols_offset);
  LIEF_DEBUG("    - String Table Offset: 0x{:x}", string_offset);

  if (string_offset == 0) {
    LIEF_WARN("Unable to find the .dynstr section");
    return;
  }

  this->stream_->setpos(dynamic_symbols_offset);
  for (size_t i = 0; i < nb_symbols; ++i) {
    if (not this->stream_->can_read<Elf_Sym>()) {
      LIEF_DEBUG("Break on symbol #{:d}", i);
      return;
    }

    const Elf_Sym symbol_header = this->stream_->read_conv<Elf_Sym>();
    std::unique_ptr<Symbol> symbol{new Symbol{&symbol_header}};

    if (symbol_header.st_name > 0) {
      if (not this->stream_->can_read<char>(string_offset + symbol_header.st_name)) {
        LIEF_DEBUG("Break on symbol #{:d}", i);
        return;
      }

      std::string name = this->stream_->peek_string_at(string_offset + symbol_header.st_name);

      if (name.empty() and i > 0) {
        LIEF_DEBUG("Symbol's name #{:d} is empty!", i);
      }

      symbol->name(name);
    }
    this->binary_->dynamic_symbols_.push_back(symbol.release());
  }
} // build_dynamic_sybols




template<typename ELF_T>
void Parser::parse_dynamic_entries(uint64_t offset, uint64_t size) {
  using Elf_Dyn  = typename ELF_T::Elf_Dyn;
  using uint__   = typename ELF_T::uint;
  using Elf_Addr = typename ELF_T::Elf_Addr;
  using Elf_Off  = typename ELF_T::Elf_Off;

  LIEF_DEBUG("== Parsing dynamic section ==");

  uint32_t nb_entries = size / sizeof(Elf_Dyn);
  nb_entries = std::min<uint32_t>(nb_entries, Parser::NB_MAX_DYNAMIC_ENTRIES);


  LIEF_DEBUG(".dynamic@0x{:x}:0x{:x} #", offset, size, nb_entries);

  Elf_Off dynamic_string_offset = this->get_dynamic_string_table();

  this->stream_->setpos(offset);
  for (size_t dynIdx = 0; dynIdx < nb_entries; ++dynIdx) {
    if (not this->stream_->can_read<Elf_Dyn>()) {
      break;
    }
    const Elf_Dyn entry = this->stream_->read_conv<Elf_Dyn>();

    std::unique_ptr<DynamicEntry> dynamic_entry;

    switch (static_cast<DYNAMIC_TAGS>(entry.d_tag)) {
      case DYNAMIC_TAGS::DT_NEEDED :
        {
          dynamic_entry = std::unique_ptr<DynamicEntryLibrary>{new DynamicEntryLibrary{&entry}};
          std::string library_name = this->stream_->peek_string_at(dynamic_string_offset + dynamic_entry->value());
          dynamic_entry->as<DynamicEntryLibrary>()->name(library_name);
          break;
        }

      case DYNAMIC_TAGS::DT_SONAME :
        {

          dynamic_entry = std::unique_ptr<DynamicSharedObject>{new DynamicSharedObject{&entry}};
          std::string sharename = this->stream_->peek_string_at(dynamic_string_offset + dynamic_entry->value());
          dynamic_entry->as<DynamicSharedObject>()->name(sharename);
          break;
        }

      case DYNAMIC_TAGS::DT_RPATH:
        {
          dynamic_entry = std::unique_ptr<DynamicEntryRpath>{new DynamicEntryRpath{&entry}};
          std::string name = this->stream_->peek_string_at(dynamic_string_offset + dynamic_entry->value());
          dynamic_entry->as<DynamicEntryRpath>()->name(name);
          break;
        }

      case DYNAMIC_TAGS::DT_RUNPATH:
        {

          dynamic_entry = std::unique_ptr<DynamicEntryRunPath>{new DynamicEntryRunPath{&entry}};
          std::string name = this->stream_->peek_string_at(dynamic_string_offset + dynamic_entry->value());
          dynamic_entry->as<DynamicEntryRunPath>()->name(name);
          break;
        }

      case DYNAMIC_TAGS::DT_FLAGS_1:
      case DYNAMIC_TAGS::DT_FLAGS:
        {
          dynamic_entry = std::unique_ptr<DynamicEntryFlags>{new DynamicEntryFlags{&entry}};
          break;
        }

      case DYNAMIC_TAGS::DT_SYMTAB:
      case DYNAMIC_TAGS::DT_SYMENT:
      case DYNAMIC_TAGS::DT_RELA:
      case DYNAMIC_TAGS::DT_RELASZ:
      case DYNAMIC_TAGS::DT_REL:
      case DYNAMIC_TAGS::DT_RELSZ:
      case DYNAMIC_TAGS::DT_JMPREL:
      case DYNAMIC_TAGS::DT_PLTRELSZ:
      case DYNAMIC_TAGS::DT_PLTREL:
      case DYNAMIC_TAGS::DT_VERSYM:
      case DYNAMIC_TAGS::DT_VERNEED:
      case DYNAMIC_TAGS::DT_VERNEEDNUM:
      case DYNAMIC_TAGS::DT_VERDEF:
      case DYNAMIC_TAGS::DT_VERDEFNUM:
        {
          dynamic_entry = std::unique_ptr<DynamicEntry>{new DynamicEntry{&entry}};
          break;
        }

      case DYNAMIC_TAGS::DT_FINI_ARRAY:
      case DYNAMIC_TAGS::DT_INIT_ARRAY:
      case DYNAMIC_TAGS::DT_PREINIT_ARRAY:
        {
          dynamic_entry = std::unique_ptr<DynamicEntryArray>{new DynamicEntryArray{&entry}};
          break;
        }

      default:
        {
          dynamic_entry = std::unique_ptr<DynamicEntry>{new DynamicEntry{&entry}};
        }
    }

    if (dynamic_entry != nullptr) {
      this->binary_->dynamic_entries_.push_back(dynamic_entry.release());
    } else {
      LIEF_WARN("dynamic_entry is nullptr !");
    }

  }

  // Check for INIT array
  // ====================
  auto&& it_dt_initarray = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry)
      {
        return entry->tag() == DYNAMIC_TAGS::DT_INIT_ARRAY;
      });

  if (it_dt_initarray != std::end(this->binary_->dynamic_entries_)) {

    auto&& it_dt_initarray_size = std::find_if(
        std::begin(this->binary_->dynamic_entries_),
        std::end(this->binary_->dynamic_entries_),
        [] (const DynamicEntry* entry)
        {
          return entry->tag() == DYNAMIC_TAGS::DT_INIT_ARRAYSZ;
        });

    DynamicEntry* dt_initarray_entry = *it_dt_initarray;

    if (it_dt_initarray_size != std::end(this->binary_->dynamic_entries_)) {
      std::vector<uint64_t>& array = dt_initarray_entry->as<DynamicEntryArray>()->array();

      const uint32_t nb_functions = static_cast<uint32_t>((*it_dt_initarray_size)->value() / sizeof(uint__));
      const Elf_Off offset = this->binary_->virtual_address_to_offset(dt_initarray_entry->value());

      this->stream_->setpos(offset);
      for (size_t i = 0; i < nb_functions; ++i) {
        if (not this->stream_->can_read<Elf_Addr>()) {
          break;
        }
        array.push_back(this->stream_->read_conv<Elf_Addr>());
      }

    } else {
      // TODO: Has DT_INIT but not DT_INIT_SIZE
    }
  }


  // Check for FINI array
  // ====================
  auto&& it_dt_finiarray = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry)
      {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_FINI_ARRAY;
      });

  if (it_dt_finiarray != std::end(this->binary_->dynamic_entries_)) {

    auto&& it_dt_finiarray_size = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry)
      {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_FINI_ARRAYSZ;
      });

    if (it_dt_finiarray_size != std::end(this->binary_->dynamic_entries_)) {

      DynamicEntry* dt_finiarray_entry = *it_dt_finiarray;

      std::vector<uint64_t>& array = dt_finiarray_entry->as<DynamicEntryArray>()->array();
      const uint32_t nb_functions = static_cast<uint32_t>((*it_dt_finiarray_size)->value() / sizeof(uint__));

      const Elf_Off offset = this->binary_->virtual_address_to_offset(dt_finiarray_entry->value());
      this->stream_->setpos(offset);
      for (size_t i = 0; i < nb_functions; ++i) {
        if (not this->stream_->can_read<Elf_Addr>()) {
          break;
        }
        array.push_back(this->stream_->read_conv<Elf_Addr>());
      }
    } else {
      //TODO
    }
  }


  // Check for PREINIT array
  // =======================
  auto&& it_dt_preinitarray = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry)
      {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_PREINIT_ARRAY;
      });

  if (it_dt_preinitarray != std::end(this->binary_->dynamic_entries_)) {

    auto&& it_dt_preinitarray_size = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry)
      {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_PREINIT_ARRAYSZ;
      });

    if (it_dt_preinitarray_size != std::end(this->binary_->dynamic_entries_)) {

      DynamicEntry* dt_preinitarray_entry = *it_dt_preinitarray;

      std::vector<uint64_t>& array = dt_preinitarray_entry->as<DynamicEntryArray>()->array();
      const uint32_t nb_functions = static_cast<uint32_t>((*it_dt_preinitarray_size)->value() / sizeof(uint__));

      const Elf_Off offset = this->binary_->virtual_address_to_offset(dt_preinitarray_entry->value());

      this->stream_->setpos(offset);
      for (size_t i = 0; i < nb_functions; ++i) {
        if (not this->stream_->can_read<Elf_Addr>()) {
          break;
        }

        array.push_back(this->stream_->read_conv<Elf_Addr>());
      }
    } else {
      //TODO: has DT_FINI but not DT_FINISZ
    }
  }
}


template<typename ELF_T, typename REL_T>
void Parser::parse_pltgot_relocations(uint64_t offset, uint64_t size) {
  static_assert(std::is_same<REL_T, typename ELF_T::Elf_Rel>::value or
                std::is_same<REL_T, typename ELF_T::Elf_Rela>::value, "REL_T must be Elf_Rel or Elf_Rela");
  using Elf_Off  = typename ELF_T::Elf_Off;

  // Already Parsed
  if (this->binary_->pltgot_relocations().size() > 0) {
    return;
  }

  const Elf_Off offset_relocations = offset;
  const uint8_t shift = std::is_same<ELF_T, ELF32>::value ? 8 : 32;

  uint32_t nb_entries = static_cast<uint32_t>(size / sizeof(REL_T));

  nb_entries = std::min<uint32_t>(nb_entries, Parser::NB_MAX_RELOCATIONS);

  this->stream_->setpos(offset_relocations);
  for (uint32_t i = 0; i < nb_entries; ++i) {
    if (not this->stream_->can_read<REL_T>()) {
      break;
    }
    const REL_T rel_hdr = this->stream_->read_conv<REL_T>();
    std::unique_ptr<Relocation> reloc{new Relocation{&rel_hdr}};
    reloc->architecture_ = this->binary_->header_.machine_type();
    reloc->purpose(RELOCATION_PURPOSES::RELOC_PURPOSE_PLTGOT);

    const uint32_t idx  = static_cast<uint32_t>(rel_hdr.r_info >> shift);
    if (idx > 0 and idx < this->binary_->dynamic_symbols_.size()) {
      reloc->symbol_ = this->binary_->dynamic_symbols_[idx];
    }

    this->binary_->relocations_.push_back(reloc.release());
  }
}

struct RelocationKey {
    uint64_t address;
    uint32_t type;
    int64_t addend;
    size_t symbol;

    bool operator==(const RelocationKey &o) const {
        return address == o.address && type == o.type && addend == o.addend && symbol == o.symbol;
    }

    bool operator<(const RelocationKey &o) const {
        return address < o.address || (address == o.address && type < o.type) ||
            ((address == o.address && type == o.type) || addend < o .addend) ||
            ((address == o.address && type == o.type && addend == o.addend) && symbol < o.symbol);
    }

    bool operator>(const RelocationKey &o) const {
        return address > o.address || (address == o.address && type > o.type) ||
            ((address == o.address && type == o.type) || addend > o.addend) ||
            ((address == o.address && type == o.type && addend == o.addend) && symbol > o.symbol);
    }
};

template<typename ELF_T, typename REL_T>
void Parser::parse_section_relocations(Section const& section) {
  using Elf_Rel = typename ELF_T::Elf_Rel;
  using Elf_Rela = typename ELF_T::Elf_Rela;

  static_assert(std::is_same<REL_T, Elf_Rel>::value or
                std::is_same<REL_T, Elf_Rela>::value, "REL_T must be Elf_Rel or Elf_Rela");

  // A relocation section can reference two other sections: a symbol table,
  // identified by the sh_info section header entry, and a section to modify,
  // identified by the sh_link
  // BUT: in practice sh_info and sh_link are inverted
  Section* applies_to = nullptr;
  if (section.information() > 0 and section.information() < this->binary_->sections_.size()) {
    const size_t sh_info = section.information();
    applies_to = this->binary_->sections_[sh_info];
  }

  // FIXME: Use it
  // Section* section_associated = nullptr;
  // if (section.link() > 0 and section.link() < this->binary_->sections_.size()) {
  //   const size_t sh_link = section.link();
  //   section_associated = this->binary_->sections_[sh_link];
  // }

  const uint64_t offset_relocations = section.file_offset();
  const uint8_t shift = std::is_same<ELF_T, ELF32>::value ? 8 : 32;

  uint32_t nb_entries = static_cast<uint32_t>(section.size() / sizeof(REL_T));
  nb_entries = std::min<uint32_t>(nb_entries, Parser::NB_MAX_RELOCATIONS);

  std::map<RelocationKey, Relocation*> map;

  this->stream_->setpos(offset_relocations);
  for (uint32_t i = 0; i < nb_entries; ++i) {
    if (not this->stream_->can_read<REL_T>()) {
      break;
    }
    const REL_T rel_hdr = this->stream_->read_conv<REL_T>();

    std::unique_ptr<Relocation> reloc{new Relocation{&rel_hdr}};
    reloc->architecture_ = this->binary_->header_.machine_type();
    reloc->section_      = applies_to;
    if (this->binary_->header().file_type() == ELF::E_TYPE::ET_REL and
        this->binary_->segments().size() == 0) {
      reloc->purpose(RELOCATION_PURPOSES::RELOC_PURPOSE_OBJECT);
    }

    const uint32_t idx  = static_cast<uint32_t>(rel_hdr.r_info >> shift);
    if (idx > 0 and idx < this->binary_->dynamic_symbols_.size()) {
      reloc->symbol_ = this->binary_->dynamic_symbols_[idx];
    } else if (idx < this->binary_->static_symbols_.size()) {
      reloc->symbol_ = this->binary_->static_symbols_[idx];
    }

    RelocationKey k = {
        reloc->address(),
        reloc->type(),
        reloc->addend(),
        reloc->has_symbol() ? LIEF::Hash::hash(reloc->symbol()) : 0
    };

    if (map[k] == nullptr) {
        auto released = map[k] = reloc.release();
        this->binary_->relocations_.push_back(released);
    }
  }
}


template<typename ELF_T>
void Parser::parse_symbol_version_requirement(uint64_t offset, uint32_t nb_entries) {
  using Elf_Verneed = typename ELF_T::Elf_Verneed;
  using Elf_Vernaux = typename ELF_T::Elf_Vernaux;

  LIEF_DEBUG("== Parser Symbol version requirement ==");

  const uint64_t svr_offset = offset;

  LIEF_DEBUG("svr offset: 0x{:x}", svr_offset);

  const uint64_t string_offset = this->get_dynamic_string_table();

  uint32_t next_symbol_offset = 0;

  for (uint32_t symbolCnt = 0; symbolCnt < nb_entries; ++symbolCnt) {
    if (not this->stream_->can_read<Elf_Verneed>(svr_offset + next_symbol_offset)) {
      break;
    }
    const Elf_Verneed header = this->stream_->peek_conv<Elf_Verneed>(svr_offset + next_symbol_offset);

    std::unique_ptr<SymbolVersionRequirement> symbol_version_requirement{new SymbolVersionRequirement{&header}};
    if (string_offset != 0) {
      std::string name = this->stream_->peek_string_at(string_offset + header.vn_file);
      symbol_version_requirement->name(name);
    }

    const uint32_t nb_symbol_aux = header.vn_cnt;

    uint32_t next_aux_offset = 0;
    if (nb_symbol_aux > 0 and header.vn_aux > 0) {
      for (uint32_t j = 0; j < nb_symbol_aux; ++j) {
        if (not this->stream_->can_read<Elf_Vernaux>(svr_offset + next_symbol_offset + header.vn_aux + next_aux_offset)) {
          break;
        }
        const Elf_Vernaux aux_header =  this->stream_->peek_conv<Elf_Vernaux>(svr_offset + next_symbol_offset + header.vn_aux + next_aux_offset);

        std::unique_ptr<SymbolVersionAuxRequirement> svar{new SymbolVersionAuxRequirement{&aux_header}};
        if (string_offset != 0) {
          svar->name(this->stream_->peek_string_at(string_offset + aux_header.vna_name));
        }

        symbol_version_requirement->symbol_version_aux_requirement_.push_back(svar.release());
        if (aux_header.vna_next == 0) break;
        next_aux_offset += aux_header.vna_next;
      }

      this->binary_->symbol_version_requirements_.push_back(symbol_version_requirement.release());
    }

    if (header.vn_next == 0) break;
    next_symbol_offset += header.vn_next;

  }


  // Associate Symbol Version with auxiliary symbol
  // Symbol version requirement is used to map
  // SymbolVersion::SymbolVersionAux <------> SymbolVersionAuxRequirement
  //
  // We mask the 15th (7FFF) bit because it sets if this symbol is a hidden on or not
  // but we don't care
  for (SymbolVersionRequirement* svr : this->binary_->symbol_version_requirements_) {
    for (SymbolVersionAuxRequirement* svar : svr->symbol_version_aux_requirement_) {
      std::for_each(
          std::begin(this->binary_->symbol_version_table_),
          std::end(this->binary_->symbol_version_table_),
          [&svar] (SymbolVersion* sv)
          {
            if ((sv->value() & 0x7FFF) == svar->other()) {
              sv->symbol_aux_ = svar;
            }
          });
    }
  }
}


template<typename ELF_T>
void Parser::parse_symbol_version_definition(uint64_t offset, uint32_t nb_entries) {
  using Elf_Verdef = typename ELF_T::Elf_Verdef;
  using Elf_Verdaux = typename ELF_T::Elf_Verdaux;

  const uint64_t string_offset = this->get_dynamic_string_table();
  uint32_t next_symbol_offset = 0;

  for (uint32_t i = 0; i < nb_entries; ++i) {
    if (not this->stream_->can_read<Elf_Verdef>(offset + next_symbol_offset)) {
      break;
    }
    const Elf_Verdef svd_header = this->stream_->peek_conv<Elf_Verdef>(offset + next_symbol_offset);

    std::unique_ptr<SymbolVersionDefinition> symbol_version_definition{new SymbolVersionDefinition{&svd_header}};
    uint32_t nb_aux_symbols = svd_header.vd_cnt;
    uint32_t next_aux_offset = 0;
    for (uint32_t j = 0; j < nb_aux_symbols; ++j) {
      if (not this->stream_->can_read<Elf_Verdaux>(offset + next_symbol_offset + svd_header.vd_aux + next_aux_offset)) {
        break;
      }

      const Elf_Verdaux svda_header = this->stream_->peek_conv<Elf_Verdaux>(offset + next_symbol_offset + svd_header.vd_aux + next_aux_offset);

      if (string_offset != 0) {
        std::string name  = this->stream_->peek_string_at(string_offset + svda_header.vda_name);
        symbol_version_definition->symbol_version_aux_.push_back(new SymbolVersionAux{name});
      }

      // Additional check
      if (svda_header.vda_next == 0) break;

      next_aux_offset += svda_header.vda_next;
    }

    this->binary_->symbol_version_definition_.push_back(symbol_version_definition.release());

    // Additional check
    if (svd_header.vd_next == 0) break;

    next_symbol_offset += svd_header.vd_next;
  }

  // Associate Symbol Version with auxiliary symbol
  // We mask the 15th bit because it sets if this symbol is a hidden on or not
  // but we don't care
  for (SymbolVersionDefinition& svd : this->binary_->symbols_version_definition()) {
    for (SymbolVersionAux* sva : svd.symbol_version_aux_) {
      std::for_each(
          std::begin(this->binary_->symbol_version_table_),
          std::end(this->binary_->symbol_version_table_),
          [&sva, &svd] (SymbolVersion* sv)
          {
            if (svd.ndx() > 1 and (sv->value() & 0x7FFF) == svd.ndx() ) {
              sv->symbol_aux_ = sva;
            }

          });
    }
  }
}

// See: https://github.com/lattera/glibc/blob/master/elf/dl-lookup.c#L860
// and  https://github.com/lattera/glibc/blob/master/elf/dl-lookup.c#L226
template<typename ELF_T>
void Parser::parse_symbol_gnu_hash(uint64_t offset) {
  using uint__  = typename ELF_T::uint;

  static constexpr uint32_t NB_MAX_WORDS   = 90000;
  static constexpr uint32_t NB_MAX_BUCKETS = 90000;
  static constexpr uint32_t MAX_NB_HASH    = 90000;

  LIEF_DEBUG("== Parser symbol GNU hash ==");
  GnuHash gnuhash;
  gnuhash.c_ = sizeof(uint__) * 8;

  this->stream_->setpos(offset);

  std::unique_ptr<uint32_t[]> header = this->stream_->read_conv_array<uint32_t>(4, /* check */false);

  if (header == nullptr) {
    LIEF_ERR("Can't read GNU hash table header");
    return;
  }

  const uint32_t nbuckets  = std::min(header[0], NB_MAX_BUCKETS);
  const uint32_t symndx    = header[1];
  const uint32_t maskwords = std::min(header[2], NB_MAX_MASKWORD);
  const uint32_t shift2    = header[3];

  gnuhash.symbol_index_ = symndx;
  gnuhash.shift2_       = shift2;

  if (maskwords & (maskwords - 1)) {
    LIEF_WARN("maskwords is not a power of 2");
  }

  if (maskwords < NB_MAX_WORDS) {
    std::vector<uint64_t> bloom_filters(maskwords);

    for (size_t i = 0; i < maskwords; ++i) {
      if (not this->stream_->can_read<uint__>()) {
        LIEF_ERR("Can't read maskwords #{:d}", i);
        break;
      }
      bloom_filters[i] = this->stream_->read_conv<uint__>();
    }
    gnuhash.bloom_filters_ = std::move(bloom_filters);

  } else {
    LIEF_ERR("GNU Hash, maskwords corrupted");
  }

  if (nbuckets > NB_MAX_BUCKETS) {
    LIEF_ERR("Number of bucket corrupted! (Too big)");
    return;
  }

  std::vector<uint32_t> buckets;
  buckets.reserve(nbuckets);

  std::unique_ptr<uint32_t[]> hash_buckets = this->stream_->read_conv_array<uint32_t>(nbuckets, false);

  if (hash_buckets != nullptr) {
    buckets = {hash_buckets.get(), hash_buckets.get() + nbuckets};
  } else {
    LIEF_ERR("GNU Hash, hash_buckets corrupted");
  }

  gnuhash.buckets_ = std::move(buckets);

  const uint32_t dynsymcount = static_cast<uint32_t>(this->binary_->dynamic_symbols_.size());
  if (dynsymcount < symndx) {
    LIEF_ERR("GNU Hash, symndx corrupted");
  } else {
    uint32_t nb_hash = dynsymcount - symndx;
    if (nb_hash < MAX_NB_HASH) {
      std::vector<uint32_t> hashvalues;
      hashvalues.reserve(nb_hash);
      std::unique_ptr<uint32_t[]> hash_values = this->stream_->read_conv_array<uint32_t>(nb_hash, /* check */ false);
      if (hash_values == nullptr) {
        LIEF_ERR("Can't read hash table");
      } else {
        hashvalues = {hash_values.get(), hash_values.get() + nb_hash};
        gnuhash.hash_values_ = std::move(hashvalues);
      }
    } else {
      LIEF_ERR("GNU Hash, nb_hash corrupted");
    }
  }
  this->binary_->gnu_hash_ = std::move(gnuhash);

}

}
}
