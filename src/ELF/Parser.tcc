/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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
void Parser::parse_binary() {
  using Elf_Off  = typename ELF_T::Elf_Off;

  LIEF_DEBUG("Start parsing");
  // Parse header
  // ============
  if (!parse_header<ELF_T>()) {
    return;
  }

  // Parse Sections
  // ==============
  try {
    if (binary_->header_.section_headers_offset() > 0) {
      parse_sections<ELF_T>();
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
    if (binary_->header_.program_headers_offset() > 0) {
      LIEF_SW_START(sw);
      parse_segments<ELF_T>();
      LIEF_SW_END("segments parsed in {}", duration_cast<std::chrono::microseconds>(sw.elapsed()));
    } else {
      if (binary_->header().file_type() != E_TYPE::ET_REL) {
        LIEF_WARN("Binary doesn't have a program header");
      }
    }
  } catch (const corrupted& e) {
    LIEF_WARN(e.what());
  }

  // Parse Dynamic elements
  // ======================

  // Find the dynamic Segment
  const auto it_segment_dynamic = std::find_if(std::begin(binary_->segments_), std::end(binary_->segments_),
      [] (const Segment* segment) {
        return segment->type() == SEGMENT_TYPES::PT_DYNAMIC;
      });

  if (it_segment_dynamic != std::end(binary_->segments_)) {

    const Elf_Off offset = (*it_segment_dynamic)->file_offset();
    const Elf_Off size   = (*it_segment_dynamic)->physical_size();

    try {
      parse_dynamic_entries<ELF_T>(offset, size);
    } catch (const exception& e) {
      LIEF_WARN(e.what());
    }
  }


  // Parse dynamic symbols
  // =====================
  const auto it_dynamic_symbol_table = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_SYMTAB;
      });

  const auto it_dynamic_symbol_size = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_SYMENT;
      });

  if (it_dynamic_symbol_table != std::end(binary_->dynamic_entries_) &&
      it_dynamic_symbol_size != std::end(binary_->dynamic_entries_)) {
    const uint64_t virtual_address = (*it_dynamic_symbol_table)->value();
    //const uint64_t size            = (*it_dynamic_symbol_size)->value();
    try {
      const uint64_t offset = binary_->virtual_address_to_offset(virtual_address);
      parse_dynamic_symbols<ELF_T>(offset);
    } catch (const LIEF::exception& e) {
      LIEF_ERR(e.what());
    }
  }

  // Parse dynamic relocations
  // =========================

  // RELA
  // ----
  auto it_dynamic_relocations = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_RELA;
      });

  auto it_dynamic_relocations_size = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_RELASZ;
      });

  if (it_dynamic_relocations != std::end(binary_->dynamic_entries_) &&
      it_dynamic_relocations_size != std::end(binary_->dynamic_entries_)) {
    const uint64_t virtual_address = (*it_dynamic_relocations)->value();
    const uint64_t size            = (*it_dynamic_relocations_size)->value();
    try {
      uint64_t offset = binary_->virtual_address_to_offset(virtual_address);
      parse_dynamic_relocations<ELF_T, typename ELF_T::Elf_Rela>(offset, size);
    } catch (const LIEF::exception& e) {
      LIEF_WARN(e.what());
    }
  }


  // REL
  // ---
  it_dynamic_relocations = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_REL;
      });

  it_dynamic_relocations_size = std::find_if(
      std::begin(binary_->dynamic_entries_),
      std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_RELSZ;
      });

  if (it_dynamic_relocations != std::end(binary_->dynamic_entries_) &&
      it_dynamic_relocations_size != std::end(binary_->dynamic_entries_)) {
    const uint64_t virtual_address = (*it_dynamic_relocations)->value();
    const uint64_t size            = (*it_dynamic_relocations_size)->value();
    try {
      const uint64_t offset = binary_->virtual_address_to_offset(virtual_address);
      parse_dynamic_relocations<ELF_T, typename ELF_T::Elf_Rel>(offset, size);
    } catch (const LIEF::exception& e) {
      LIEF_WARN(e.what());
    }

  }

  // Parse PLT/GOT Relocations
  // ==========================
  const auto it_pltgot_relocations = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_JMPREL;
      });

  const auto it_pltgot_relocations_size = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_PLTRELSZ;
      });

  const auto it_pltgot_relocations_type = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_PLTREL;
      });

  if (it_pltgot_relocations != std::end(binary_->dynamic_entries_) &&
      it_pltgot_relocations_size != std::end(binary_->dynamic_entries_)) {
    const uint64_t virtual_address = (*it_pltgot_relocations)->value();
    const uint64_t size            = (*it_pltgot_relocations_size)->value();
    DYNAMIC_TAGS type;
    if (it_pltgot_relocations_type != std::end(binary_->dynamic_entries_)) {
      type = static_cast<DYNAMIC_TAGS>((*it_pltgot_relocations_type)->value());
    } else {
      // Try to guess: We assume that on ELF64 -> DT_RELA and on ELF32 -> DT_REL
      if (std::is_same<ELF_T, details::ELF64>::value) {
        type = DYNAMIC_TAGS::DT_RELA;
      } else {
        type = DYNAMIC_TAGS::DT_REL;
      }
    }

    try {
      const uint64_t offset = binary_->virtual_address_to_offset(virtual_address);
      if (type == DYNAMIC_TAGS::DT_RELA) {
        parse_pltgot_relocations<ELF_T, typename ELF_T::Elf_Rela>(offset, size);
      } else {
        parse_pltgot_relocations<ELF_T, typename ELF_T::Elf_Rel>(offset, size);
      }
    } catch (const LIEF::exception& e) {
      LIEF_WARN(e.what());

    }


  }

  // Parse Symbol Version
  // ====================
  const auto it_symbol_versions = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_VERSYM;
      });

  if (it_symbol_versions != std::end(binary_->dynamic_entries_)) {
    const uint64_t virtual_address = (*it_symbol_versions)->value();
    try {
      uint64_t offset = binary_->virtual_address_to_offset(virtual_address);
      parse_symbol_version(offset);
    } catch (const LIEF::exception&) {

    }

  }

  // Parse Symbol Version Requirement
  // ================================
  const auto it_symbol_version_requirement = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_VERNEED;
      });

  const auto it_symbol_version_requirement_size = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_VERNEEDNUM;
      });

  if (it_symbol_version_requirement != std::end(binary_->dynamic_entries_) &&
      it_symbol_version_requirement_size != std::end(binary_->dynamic_entries_)) {

    const DynamicEntry* dt_verneed     = *it_symbol_version_requirement;
    const DynamicEntry* dt_verneed_num = *it_symbol_version_requirement_size;

    const uint64_t virtual_address = dt_verneed->value();
    const uint32_t nb_entries = std::min(Parser::NB_MAX_SYMBOLS, static_cast<uint32_t>(dt_verneed_num->value()));
    try {
      const uint64_t offset = binary_->virtual_address_to_offset(virtual_address);
      parse_symbol_version_requirement<ELF_T>(offset, nb_entries);
    } catch (const LIEF::exception& e) {
      LIEF_WARN("{}", e.what());
    }

  }

  // Parse Symbol Version Definition
  // ===============================
  const auto it_symbol_version_definition = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_VERDEF;
      });

  const auto it_symbol_version_definition_size = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_VERDEFNUM;
      });

  if (it_symbol_version_definition != std::end(binary_->dynamic_entries_) &&
      it_symbol_version_definition_size != std::end(binary_->dynamic_entries_)) {
    const uint64_t virtual_address = (*it_symbol_version_definition)->value();
    const uint32_t size            = static_cast<uint32_t>((*it_symbol_version_definition_size)->value());
    try {
      const uint64_t offset = binary_->virtual_address_to_offset(virtual_address);
      parse_symbol_version_definition<ELF_T>(offset, size);
    } catch (const LIEF::exception&) {

    }

  }


  // Parse static symbols
  // ====================
  auto it_symtab_section = std::find_if(
      std::begin(binary_->sections_), std::end(binary_->sections_),
      [] (const Section* section) {
        return section->type() == ELF_SECTION_TYPES::SHT_SYMTAB;
      });

  if (it_symtab_section != std::end(binary_->sections_)) {
    const Section* section = *it_symtab_section;
    uint32_t nb_entries = static_cast<uint32_t>((section->size() / sizeof(typename ELF_T::Elf_Sym)));

    if (section->link() == 0 || section->link() >= binary_->sections_.size()) {
      LIEF_WARN("section->link() is not valid !");
    } else {
      // We should have:
      // nb_entries == section->information())
      // but lots of compiler not respect this rule
      parse_static_symbols<ELF_T>(
          section->file_offset(),
          nb_entries,
          binary_->sections_[section->link()]);
    }

    it_symtab_section = std::find_if(
        it_symtab_section + 1,
        std::end(binary_->sections_),
        [] (const Section* section)
        {
        return section != nullptr && section->type() == ELF_SECTION_TYPES::SHT_SYMTAB;
        });

    if (it_symtab_section != std::end(binary_->sections_)) {
      LIEF_WARN("Support for multiple SHT_SYMTAB section is not implemented");
    }
  }


  // Parse Symbols's hash
  // ====================

  const auto it_symbol_hash = std::find_if(std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_HASH;
      });

  const auto it_symbol_gnu_hash = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_GNU_HASH;
      });

  if (it_symbol_hash != std::end(binary_->dynamic_entries_)) {
    try {
      const uint64_t symbol_sys_hash_offset = binary_->virtual_address_to_offset((*it_symbol_hash)->value());
      parse_symbol_sysv_hash(symbol_sys_hash_offset);
    } catch (const conversion_error&) {
    } catch (const exception& e) {
      LIEF_WARN("{}", e.what());
    }
  }


  if (it_symbol_gnu_hash != std::end(binary_->dynamic_entries_)) {
    try {
      const uint64_t symbol_gnu_hash_offset = binary_->virtual_address_to_offset((*it_symbol_gnu_hash)->value());
      parse_symbol_gnu_hash<ELF_T>(symbol_gnu_hash_offset);
    } catch (const conversion_error&) {
    } catch (const exception& e) {
      LIEF_WARN("{}", e.what());
    }
  }

  // Parse Note segment
  // ==================
  for (const Segment& segment : binary_->segments()) {
    if (segment.type() != SEGMENT_TYPES::PT_NOTE) {
      continue;
    }
    try {
      const uint64_t note_offset = binary_->virtual_address_to_offset(segment.virtual_address());
      parse_notes(note_offset, segment.physical_size());
    } catch (const conversion_error&) {
    } catch (const exception& e) {
      LIEF_WARN("{}", e.what());
    }

  }

  // Parse Note Sections
  // ===================
  for (const Section& section : binary_->sections()) {
    if (section.type() != ELF_SECTION_TYPES::SHT_NOTE) {
      continue;
    }

    try {
      parse_notes(section.offset(), section.size());
    } catch (const conversion_error&) {
    } catch (const exception& e) {
      LIEF_WARN("{}", e.what());
    }


  }

  // Try to parse using sections
  // If we don't have any relocations, we parse all relocation sections
  // otherwise, only the non-allocated sections to avoid parsing dynamic
  // relocations (or plt relocations) twice.
  bool skip_allocated_sections = binary_->relocations_.size() > 0;
  for (const Section& section : binary_->sections()) {
    if(skip_allocated_sections && section.has(ELF_SECTION_FLAGS::SHF_ALLOC)){
      continue;
    }
    try {
      if (section.type() == ELF_SECTION_TYPES::SHT_REL) {
        parse_section_relocations<ELF_T, typename ELF_T::Elf_Rel>(section);
      }
      else if (section.type() == ELF_SECTION_TYPES::SHT_RELA) {
        parse_section_relocations<ELF_T, typename ELF_T::Elf_Rela>(section);
      }

    } catch (const exception& e) {
      LIEF_WARN("Unable to parse relocations from section '{}' ({})", section.name(), e.what());
    }
  }

  link_symbol_version();
  parse_overlay();
}


template<typename ELF_T>
bool Parser::parse_header() {
  using Elf_Ehdr = typename ELF_T::Elf_Ehdr;

  LIEF_DEBUG("[+] Parsing Header");
  stream_->setpos(0);
  if (stream_->can_read<Elf_Ehdr>()) {
    Elf_Ehdr hdr = stream_->read_conv<Elf_Ehdr>();
    binary_->header_ = hdr;
    return true;
  } else {
    LIEF_ERR("Can't read header!");
    return false;
  }
}


template<typename ELF_T>
uint32_t Parser::get_numberof_dynamic_symbols(DYNSYM_COUNT_METHODS mtd) const {

  switch(mtd) {
    case DYNSYM_COUNT_METHODS::COUNT_HASH:        return nb_dynsym_hash<ELF_T>();
    case DYNSYM_COUNT_METHODS::COUNT_SECTION:     return nb_dynsym_section<ELF_T>();
    case DYNSYM_COUNT_METHODS::COUNT_RELOCATIONS: return nb_dynsym_relocations<ELF_T>();

    case DYNSYM_COUNT_METHODS::COUNT_AUTO:
    default:
      {
        uint32_t nb_dynsym, nb_dynsym_tmp = 0;

        nb_dynsym = get_numberof_dynamic_symbols<ELF_T>(DYNSYM_COUNT_METHODS::COUNT_RELOCATIONS);

        nb_dynsym_tmp = get_numberof_dynamic_symbols<ELF_T>(DYNSYM_COUNT_METHODS::COUNT_SECTION);

        if (nb_dynsym_tmp < Parser::NB_MAX_SYMBOLS &&
            nb_dynsym_tmp > nb_dynsym &&
            (nb_dynsym_tmp - nb_dynsym) < Parser::DELTA_NB_SYMBOLS) {
          nb_dynsym = nb_dynsym_tmp;
        }

        nb_dynsym_tmp = get_numberof_dynamic_symbols<ELF_T>(DYNSYM_COUNT_METHODS::COUNT_HASH);

        if (nb_dynsym_tmp < Parser::NB_MAX_SYMBOLS &&
            nb_dynsym_tmp > nb_dynsym &&
            (nb_dynsym_tmp - nb_dynsym) < Parser::DELTA_NB_SYMBOLS) {
          nb_dynsym = nb_dynsym_tmp;
        }

        return nb_dynsym;
      }
  }
}

template<typename ELF_T>
uint32_t Parser::nb_dynsym_relocations() const {
  uint32_t nb_symbols = 0;

  // Dynamic Relocations
  // ===================

  // RELA
  // ----
  auto it_dynamic_relocations = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_RELA;
      });

  auto it_dynamic_relocations_size = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_RELASZ;
      });

  if (it_dynamic_relocations      != std::end(binary_->dynamic_entries_) &&
      it_dynamic_relocations_size != std::end(binary_->dynamic_entries_)) {
    const uint64_t virtual_address = (*it_dynamic_relocations)->value();
    const uint64_t size            = (*it_dynamic_relocations_size)->value();
    try {
      uint64_t offset = binary_->virtual_address_to_offset(virtual_address);
      nb_symbols = std::max(nb_symbols, max_relocation_index<ELF_T, typename ELF_T::Elf_Rela>(offset, size));
    } catch (const LIEF::exception&) {
    }
  }


  // REL
  // ---
  it_dynamic_relocations = std::find_if(
      std::begin(binary_->dynamic_entries_),
      std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr && entry->tag() == DYNAMIC_TAGS::DT_REL;
      });

  it_dynamic_relocations_size = std::find_if(
      std::begin(binary_->dynamic_entries_),
      std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr && entry->tag() == DYNAMIC_TAGS::DT_RELSZ;
      });

  if (it_dynamic_relocations != std::end(binary_->dynamic_entries_) &&
      it_dynamic_relocations_size != std::end(binary_->dynamic_entries_)) {
    const uint64_t virtual_address = (*it_dynamic_relocations)->value();
    const uint64_t size            = (*it_dynamic_relocations_size)->value();
    try {
      const uint64_t offset = binary_->virtual_address_to_offset(virtual_address);
      nb_symbols = std::max(nb_symbols, max_relocation_index<ELF_T, typename ELF_T::Elf_Rel>(offset, size));
    } catch (const LIEF::exception&) {

    }

  }

  // Parse PLT/GOT Relocations
  // ==========================
  const auto it_pltgot_relocations = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_JMPREL;
      });

  const auto it_pltgot_relocations_size = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_PLTRELSZ;
      });

  const auto it_pltgot_relocations_type = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_PLTREL;
      });

  if (it_pltgot_relocations != std::end(binary_->dynamic_entries_) &&
      it_pltgot_relocations_size != std::end(binary_->dynamic_entries_)) {
    const uint64_t virtual_address = (*it_pltgot_relocations)->value();
    const uint64_t size            = (*it_pltgot_relocations_size)->value();
    DYNAMIC_TAGS type;
    if (it_pltgot_relocations_type != std::end(binary_->dynamic_entries_)) {
      type = static_cast<DYNAMIC_TAGS>((*it_pltgot_relocations_type)->value());
    } else {
      // Try to guess: We assume that on ELF64 -> DT_RELA and on ELF32 -> DT_REL
      if (std::is_same<ELF_T, details::ELF64>::value) {
        type = DYNAMIC_TAGS::DT_RELA;
      } else {
        type = DYNAMIC_TAGS::DT_REL;
      }
    }

    try {
      const uint64_t offset = binary_->virtual_address_to_offset(virtual_address);
      if (type == DYNAMIC_TAGS::DT_RELA) {
        nb_symbols = std::max(nb_symbols, max_relocation_index<ELF_T, typename ELF_T::Elf_Rela>(offset, size));
      } else {
        nb_symbols = std::max(nb_symbols, max_relocation_index<ELF_T, typename ELF_T::Elf_Rel>(offset, size));
      }
    } catch (const LIEF::exception& e) {
      LIEF_WARN("{}", e.what());
    }
  }

  return nb_symbols;
}

template<typename ELF_T, typename REL_T>
uint32_t Parser::max_relocation_index(uint64_t relocations_offset, uint64_t size) const {
  static_assert(std::is_same<REL_T, typename ELF_T::Elf_Rel>::value ||
                std::is_same<REL_T, typename ELF_T::Elf_Rela>::value, "REL_T must be Elf_Rel || Elf_Rela");

  const uint8_t shift = std::is_same<ELF_T, details::ELF32>::value ? 8 : 32;

  const uint32_t nb_entries = static_cast<uint32_t>(size / sizeof(REL_T));

  uint32_t idx = 0;
  stream_->setpos(relocations_offset);
  for (uint32_t i = 0; i < nb_entries; ++i) {
    if (!stream_->can_read<REL_T>()) {
      break;
    }
    const REL_T reloc_entry = stream_->read_conv<REL_T>();
    idx = std::max(idx, static_cast<uint32_t>(reloc_entry.r_info >> shift));
  }
  return (idx + 1);
} // max_relocation_index



template<typename ELF_T>
uint32_t Parser::nb_dynsym_section() const {
  using Elf_Sym = typename ELF_T::Elf_Sym;
  using Elf_Off = typename ELF_T::Elf_Off;

  const auto it_dynamic_section = std::find_if(std::begin(binary_->sections_), std::end(binary_->sections_),
                                         [] (const Section* section) {
                                           return section->type() == ELF_SECTION_TYPES::SHT_DYNSYM;
                                         });

  if (it_dynamic_section == std::end(binary_->sections_)) {
    return 0;
  }

  const Elf_Off section_size = (*it_dynamic_section)->size();
  const auto nb_symbols = static_cast<uint32_t>((section_size / sizeof(Elf_Sym)));
  return nb_symbols;
}

template<typename ELF_T>
uint32_t Parser::nb_dynsym_hash() const {

  if (binary_->has(DYNAMIC_TAGS::DT_HASH)) {
    return nb_dynsym_sysv_hash<ELF_T>();
  }

  if (binary_->has(DYNAMIC_TAGS::DT_GNU_HASH)) {
    return nb_dynsym_gnu_hash<ELF_T>();
  }

  return 0;
}


template<typename ELF_T>
uint32_t Parser::nb_dynsym_sysv_hash() const {
  using Elf_Off  = typename ELF_T::Elf_Off;

  const DynamicEntry& dyn_hash = binary_->get(DYNAMIC_TAGS::DT_HASH);
  const Elf_Off sysv_hash_offset = binary_->virtual_address_to_offset(dyn_hash.value());

  // From the doc: 'so nchain should equal the number of symbol table entries.'

  stream_->setpos(sysv_hash_offset + sizeof(uint32_t));
  if (stream_->can_read<uint32_t>()) {
    const size_t nb_symbols = stream_->read_conv<uint32_t>();
    return nb_symbols;
  }

  return 0;
}

template<typename ELF_T>
uint32_t Parser::nb_dynsym_gnu_hash() const {
  using uint__ = typename ELF_T::uint;
  using Elf_Off  = typename ELF_T::Elf_Off;

  const DynamicEntry& dyn_hash = binary_->get(DYNAMIC_TAGS::DT_GNU_HASH);
  const Elf_Off gnu_hash_offset = binary_->virtual_address_to_offset(dyn_hash.value());


  stream_->setpos(gnu_hash_offset);
  if (!stream_->can_read<uint32_t>()) {
    return 0;
  }

  const uint32_t nbuckets  = stream_->read_conv<uint32_t>();
  if (!stream_->can_read<uint32_t>()) {
    return 0;
  }

  const uint32_t symndx    = stream_->read_conv<uint32_t>();

  if (!stream_->can_read<uint32_t>()) {
    return 0;
  }

  const uint32_t maskwords = stream_->read_conv<uint32_t>();

  // skip shift2, unused as we don't need the bloom filter to count syms.
  stream_->increment_pos(sizeof(uint32_t));

  if (maskwords & (maskwords - 1)) {
    LIEF_WARN("maskwords is not a power of 2");
    return 0;
  }

  if (maskwords > Parser::NB_MAX_MASKWORD) {
    return 0;
  }

  // skip bloom filter mask words
  stream_->increment_pos(sizeof(uint__) * (maskwords));

  uint32_t max_bucket = 0;
  for (size_t i = 0; i < nbuckets; ++i) {

    if (!stream_->can_read<uint32_t>()) {
      return 0;
    }

    uint32_t bucket = stream_->read_conv<uint32_t>();
    if (bucket > max_bucket) {
      max_bucket = bucket;
    }
  }

  if (max_bucket == 0) {
    return 0;
  }

  // Skip to the contents of the bucket with the largest symbol index
  stream_->increment_pos(sizeof(uint32_t) * (max_bucket - symndx));

  // Count values in the bucket
  uint32_t hash_value = 0;
  size_t nsyms = 0;
  do {
    if (!stream_->can_read<uint32_t>()) {
      return 0;
    }
    hash_value = stream_->read_conv<uint32_t>();

    nsyms++;
  } while ((hash_value & 1) == 0); // "It is set to 1 when a symbol is the last symbol in a given hash bucket"

  return max_bucket + nsyms;
}

template<typename ELF_T>
void Parser::parse_sections() {
  using Elf_Shdr = typename ELF_T::Elf_Shdr;

  using Elf_Off  = typename ELF_T::Elf_Off;
  LIEF_DEBUG("Parsing Section");

  const Elf_Off shdr_offset = binary_->header_.section_headers_offset();
  const uint32_t numberof_sections = std::min<uint32_t>(binary_->header_.numberof_sections(), Parser::NB_MAX_SECTION);

  stream_->setpos(shdr_offset);
  std::unordered_map<Section*, size_t> sections_names;
  for (size_t i = 0; i < numberof_sections; ++i) {
    LIEF_DEBUG("    Section #{:02d}", i);
    if (!stream_->can_read<Elf_Shdr>()) {
      LIEF_ERR("  Can't parse section #{:02d}", i);
      break;
    }

    const Elf_Shdr shdr = stream_->read_conv<Elf_Shdr>();

    std::unique_ptr<Section> section{new Section{shdr}};
    section->datahandler_ = binary_->datahandler_;

    uint64_t section_end = section->file_offset();
    section_end += section->size();

    if (section_end > stream_->size() + 200_MB) {
      LIEF_ERR("  Section #{:d} is too large!", i);
      continue;
    }

    binary_->datahandler_->create(section->file_offset(), section->size(), DataHandler::Node::SECTION);

    // Only if it contains data (with bits)
    if (section->size() > 0 && section->size() < Parser::MAX_SECTION_SIZE) {

      const Elf_Off offset_to_content   = section->file_offset();
      const Elf_Off size                = section->size();
      binary_->datahandler_->reserve(section->file_offset(), section->size());

      const uint8_t* content = stream_->peek_array<uint8_t>(offset_to_content, size, /* check */false);
      if (content == nullptr) {
        if (section->type() != ELF_SECTION_TYPES::SHT_NOBITS) {
          LIEF_WARN("  Unable to get content of section #{:d}", i);
        }
      } else {
        section->content({content, content + size});
      }
    }
    sections_names[section.get()] = shdr.sh_name;
    binary_->sections_.push_back(section.release());
  }

  LIEF_DEBUG("    Parse section names");
  // Parse name
  if (binary_->header_.section_name_table_idx() < binary_->sections_.size()) {
    const size_t section_string_index = binary_->header_.section_name_table_idx();
    const Section* string_section = binary_->sections_[section_string_index];
    for (Section* section : binary_->sections_) {
      const auto it_name_idx = sections_names.find(section);
      if (it_name_idx == std::end(sections_names)) {
        LIEF_WARN("Missing name_idx for section at offset 0x{:x}", section->file_offset());
        continue;
      }
      const size_t name_offset = it_name_idx->second;
      std::string name = stream_->peek_string_at(string_section->file_offset() + name_offset);
      section->name(name);
    }
  } else {
    LIEF_WARN("Unable to fetch the string section");
  }
}

template<typename ELF_T>
void Parser::parse_segments() {
  using Elf_Phdr = typename ELF_T::Elf_Phdr;
  using Elf_Off  = typename ELF_T::Elf_Off;

  static const auto check_section_in_segment =
    [] (const Section* section, const Segment* segment) {
      if (section->virtual_address() > 0) {
        return section->virtual_address() >= segment->virtual_address() &&
          (section->virtual_address() + section->size()) <=
          (segment->virtual_address() + segment->virtual_size());
      } else if (section->file_offset() > 0) {
        return section->file_offset() >= segment->file_offset() &&
              (section->file_offset() + section->size()) < (segment->file_offset() + segment->physical_size());
      }
      return false;
    };

  LIEF_DEBUG("== Parse Segments ==");
  const Elf_Off segment_headers_offset = binary_->header().program_headers_offset();
  const uint32_t nbof_segments         = std::min<uint32_t>(binary_->header().numberof_segments(), Parser::NB_MAX_SEGMENTS);

  stream_->setpos(segment_headers_offset);

  for (size_t i = 0; i < nbof_segments; ++i) {
    if (!stream_->can_read<Elf_Phdr>()) {
      LIEF_ERR("Can't parse segement #{:d}", i);
      break;
    }
    const Elf_Phdr segment_headers = stream_->read_conv<Elf_Phdr>();

    std::unique_ptr<Segment> segment{new Segment{segment_headers}};
    segment->datahandler_ = binary_->datahandler_;

    binary_->datahandler_->create(segment->file_offset(), segment->physical_size(), DataHandler::Node::SEGMENT);

    if (segment->physical_size() > 0 && segment->physical_size() < Parser::MAX_SEGMENT_SIZE) {

      const Elf_Off offset_to_content   = segment->file_offset();
      const Elf_Off size                = segment->physical_size();
      binary_->datahandler_->reserve(segment->file_offset(), segment->physical_size());
      const uint8_t* content = stream_->peek_array<uint8_t>(offset_to_content, size, /* check */false);
      if (content != nullptr) {
        segment->content({content, content + size});
        if (segment->type() == SEGMENT_TYPES::PT_INTERP) {
          binary_->interpreter_ = stream_->peek_string_at(offset_to_content, segment->physical_size());
        }
      } else {
        LIEF_ERR("Unable to get content of segment #{:d}", i);
      }
    }

    for (Section* section : binary_->sections_) {
      if (check_section_in_segment(section, segment.get())) {
        section->segments_.push_back(segment.get());
        segment->sections_.push_back(section);
      }
    }
    binary_->segments_.push_back(segment.release());
  }

}



template<typename ELF_T, typename REL_T>
void Parser::parse_dynamic_relocations(uint64_t relocations_offset, uint64_t size) {
  static_assert(std::is_same<REL_T, typename ELF_T::Elf_Rel>::value ||
                std::is_same<REL_T, typename ELF_T::Elf_Rela>::value, "REL_T must be Elf_Rel || Elf_Rela");
  LIEF_DEBUG("== Parsing dynamic relocations ==");

  // Already parsed
  if (binary_->dynamic_relocations().size() > 0) {
    return;
  }

  const uint8_t shift = std::is_same<ELF_T, details::ELF32>::value ? 8 : 32;

  uint32_t nb_entries = static_cast<uint32_t>(size / sizeof(REL_T));

  nb_entries = std::min<uint32_t>(nb_entries, Parser::NB_MAX_RELOCATIONS);

  stream_->setpos(relocations_offset);
  for (uint32_t i = 0; i < nb_entries; ++i) {
    if (!stream_->can_read<REL_T>()) {
      break;
    }
    const REL_T raw_reloc = stream_->read_conv<REL_T>();
    std::unique_ptr<Relocation> reloc{new Relocation{raw_reloc}};
    reloc->purpose(RELOCATION_PURPOSES::RELOC_PURPOSE_DYNAMIC);
    reloc->architecture_ = binary_->header().machine_type();

    const uint32_t idx =  static_cast<uint32_t>(raw_reloc.r_info >> shift);

    if (idx < binary_->dynamic_symbols_.size()) {
      reloc->symbol_ = binary_->dynamic_symbols_[idx];
    } else {
      LIEF_WARN("Unable to find the symbol associated with the relocation (idx: {}) {}", idx, *reloc);
    }

    binary_->relocations_.push_back(reloc.release());
  }
} // build_dynamic_reclocations



template<typename ELF_T>
void Parser::parse_static_symbols(uint64_t offset, uint32_t nbSymbols, const Section* string_section) {

  using Elf_Sym = typename ELF_T::Elf_Sym;
  LIEF_DEBUG("== Parsing static symbols ==");

  stream_->setpos(offset);
  for (uint32_t i = 0; i < nbSymbols; ++i) {
    if (!stream_->can_read<Elf_Sym>()) {
      break;
    }
    const Elf_Sym raw_sym = stream_->read_conv<Elf_Sym>();

    std::unique_ptr<Symbol> symbol{new Symbol{raw_sym}};
    std::string symbol_name = stream_->peek_string_at(string_section->file_offset() + raw_sym.st_name);
    symbol->name(symbol_name);
    binary_->static_symbols_.push_back(symbol.release());
  }
} // build_static_symbols


template<typename ELF_T>
void Parser::parse_dynamic_symbols(uint64_t offset) {
  using Elf_Sym = typename ELF_T::Elf_Sym;
  using Elf_Off = typename ELF_T::Elf_Off;

  LIEF_DEBUG("== Parsing dynamics symbols ==");

  uint32_t nb_symbols = get_numberof_dynamic_symbols<ELF_T>(count_mtd_);

  const Elf_Off dynamic_symbols_offset = offset;
  const Elf_Off string_offset          = get_dynamic_string_table();

  LIEF_DEBUG("    - Number of symbols counted: {:d}", nb_symbols);
  LIEF_DEBUG("    - Table Offset: 0x{:x}", dynamic_symbols_offset);
  LIEF_DEBUG("    - String Table Offset: 0x{:x}", string_offset);

  if (string_offset == 0) {
    LIEF_WARN("Unable to find the .dynstr section");
    return;
  }

  stream_->setpos(dynamic_symbols_offset);
  for (size_t i = 0; i < nb_symbols; ++i) {
    if (!stream_->can_read<Elf_Sym>()) {
      LIEF_DEBUG("Break on symbol #{:d}", i);
      return;
    }

    const Elf_Sym symbol_header = stream_->read_conv<Elf_Sym>();
    std::unique_ptr<Symbol> symbol{new Symbol{symbol_header}};

    if (symbol_header.st_name > 0) {
      if (!stream_->can_read<char>(string_offset + symbol_header.st_name)) {
        LIEF_DEBUG("Break on symbol #{:d}", i);
        return;
      }

      std::string name = stream_->peek_string_at(string_offset + symbol_header.st_name);

      if (name.empty() && i > 0) {
        LIEF_DEBUG("Symbol's name #{:d} is empty!", i);
      }

      symbol->name(name);
    }
    binary_->dynamic_symbols_.push_back(symbol.release());
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

  Elf_Off dynamic_string_offset = get_dynamic_string_table();

  bool end_of_dynamic = false;
  stream_->setpos(offset);
  for (size_t dynIdx = 0; dynIdx < nb_entries; ++dynIdx) {
    if (!stream_->can_read<Elf_Dyn>()) {
      break;
    }
    const Elf_Dyn entry = stream_->read_conv<Elf_Dyn>();

    std::unique_ptr<DynamicEntry> dynamic_entry;

    switch (static_cast<DYNAMIC_TAGS>(entry.d_tag)) {
      case DYNAMIC_TAGS::DT_NEEDED :
        {
          dynamic_entry = std::unique_ptr<DynamicEntryLibrary>{new DynamicEntryLibrary{entry}};
          std::string library_name = stream_->peek_string_at(dynamic_string_offset + dynamic_entry->value());
          dynamic_entry->as<DynamicEntryLibrary>()->name(library_name);
          break;
        }

      case DYNAMIC_TAGS::DT_SONAME :
        {

          dynamic_entry = std::unique_ptr<DynamicSharedObject>{new DynamicSharedObject{entry}};
          std::string sharename = stream_->peek_string_at(dynamic_string_offset + dynamic_entry->value());
          dynamic_entry->as<DynamicSharedObject>()->name(sharename);
          break;
        }

      case DYNAMIC_TAGS::DT_RPATH:
        {
          dynamic_entry = std::unique_ptr<DynamicEntryRpath>{new DynamicEntryRpath{entry}};
          std::string name = stream_->peek_string_at(dynamic_string_offset + dynamic_entry->value());
          dynamic_entry->as<DynamicEntryRpath>()->name(name);
          break;
        }

      case DYNAMIC_TAGS::DT_RUNPATH:
        {

          dynamic_entry = std::unique_ptr<DynamicEntryRunPath>{new DynamicEntryRunPath{entry}};
          std::string name = stream_->peek_string_at(dynamic_string_offset + dynamic_entry->value());
          dynamic_entry->as<DynamicEntryRunPath>()->name(name);
          break;
        }

      case DYNAMIC_TAGS::DT_FLAGS_1:
      case DYNAMIC_TAGS::DT_FLAGS:
        {
          dynamic_entry = std::unique_ptr<DynamicEntryFlags>{new DynamicEntryFlags{entry}};
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
          dynamic_entry = std::unique_ptr<DynamicEntry>{new DynamicEntry{entry}};
          break;
        }

      case DYNAMIC_TAGS::DT_FINI_ARRAY:
      case DYNAMIC_TAGS::DT_INIT_ARRAY:
      case DYNAMIC_TAGS::DT_PREINIT_ARRAY:
        {
          dynamic_entry = std::unique_ptr<DynamicEntryArray>{new DynamicEntryArray{entry}};
          break;
        }

      case DYNAMIC_TAGS::DT_NULL:
        {
          dynamic_entry = std::unique_ptr<DynamicEntry>{new DynamicEntry{entry}};
          end_of_dynamic = true;
          break;
        }

      default:
        {
          dynamic_entry = std::unique_ptr<DynamicEntry>{new DynamicEntry{entry}};
        }
    }

    if (dynamic_entry != nullptr) {
      binary_->dynamic_entries_.push_back(dynamic_entry.release());
    } else {
      LIEF_WARN("dynamic_entry is nullptr !");
    }

    if (end_of_dynamic) {
      break;
    }

  }

  // Check for INIT array
  // ====================
  const auto it_dt_initarray = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_INIT_ARRAY;
      });

  if (it_dt_initarray != std::end(binary_->dynamic_entries_)) {

    const auto it_dt_initarray_size = std::find_if(
        std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
        [] (const DynamicEntry* entry) {
          return entry->tag() == DYNAMIC_TAGS::DT_INIT_ARRAYSZ;
        });

    DynamicEntry* dt_initarray_entry = *it_dt_initarray;

    if (it_dt_initarray_size != std::end(binary_->dynamic_entries_)) {
      std::vector<uint64_t>& array = dt_initarray_entry->as<DynamicEntryArray>()->array();

      const auto nb_functions = static_cast<uint32_t>((*it_dt_initarray_size)->value() / sizeof(uint__));
      const Elf_Off offset = binary_->virtual_address_to_offset(dt_initarray_entry->value());

      stream_->setpos(offset);
      for (size_t i = 0; i < nb_functions; ++i) {
        if (!stream_->can_read<Elf_Addr>()) {
          break;
        }
        array.push_back(stream_->read_conv<Elf_Addr>());
      }

    } else {
      // TODO: Has DT_INIT but not DT_INIT_SIZE
    }
  }


  // Check for FINI array
  // ====================
  const auto it_dt_finiarray = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_FINI_ARRAY;
      });

  if (it_dt_finiarray != std::end(binary_->dynamic_entries_)) {
    const auto it_dt_finiarray_size = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_FINI_ARRAYSZ;
      });

    if (it_dt_finiarray_size != std::end(binary_->dynamic_entries_)) {

      DynamicEntry* dt_finiarray_entry = *it_dt_finiarray;

      std::vector<uint64_t>& array = dt_finiarray_entry->as<DynamicEntryArray>()->array();
      const auto nb_functions = static_cast<uint32_t>((*it_dt_finiarray_size)->value() / sizeof(uint__));

      const Elf_Off offset = binary_->virtual_address_to_offset(dt_finiarray_entry->value());
      stream_->setpos(offset);
      for (size_t i = 0; i < nb_functions; ++i) {
        if (!stream_->can_read<Elf_Addr>()) {
          break;
        }
        array.push_back(stream_->read_conv<Elf_Addr>());
      }
    } else {
      //TODO
    }
  }


  // Check for PREINIT array
  // =======================
  const auto it_dt_preinitarray = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_PREINIT_ARRAY;
      });

  if (it_dt_preinitarray != std::end(binary_->dynamic_entries_)) {

    const auto it_dt_preinitarray_size = std::find_if(
      std::begin(binary_->dynamic_entries_), std::end(binary_->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry->tag() == DYNAMIC_TAGS::DT_PREINIT_ARRAYSZ;
      });

    if (it_dt_preinitarray_size != std::end(binary_->dynamic_entries_)) {

      DynamicEntry* dt_preinitarray_entry = *it_dt_preinitarray;

      std::vector<uint64_t>& array = dt_preinitarray_entry->as<DynamicEntryArray>()->array();
      const uint32_t nb_functions = static_cast<uint32_t>((*it_dt_preinitarray_size)->value() / sizeof(uint__));

      const Elf_Off offset = binary_->virtual_address_to_offset(dt_preinitarray_entry->value());

      stream_->setpos(offset);
      for (size_t i = 0; i < nb_functions; ++i) {
        if (!stream_->can_read<Elf_Addr>()) {
          break;
        }

        array.push_back(stream_->read_conv<Elf_Addr>());
      }
    } else {
      //TODO: has DT_FINI but not DT_FINISZ
    }
  }
}


template<typename ELF_T, typename REL_T>
void Parser::parse_pltgot_relocations(uint64_t offset, uint64_t size) {
  static_assert(std::is_same<REL_T, typename ELF_T::Elf_Rel>::value ||
                std::is_same<REL_T, typename ELF_T::Elf_Rela>::value, "REL_T must be Elf_Rel || Elf_Rela");
  using Elf_Off  = typename ELF_T::Elf_Off;

  // Already Parsed
  if (binary_->pltgot_relocations().size() > 0) {
    return;
  }

  const Elf_Off offset_relocations = offset;
  const uint8_t shift = std::is_same<ELF_T, details::ELF32>::value ? 8 : 32;

  uint32_t nb_entries = static_cast<uint32_t>(size / sizeof(REL_T));

  nb_entries = std::min<uint32_t>(nb_entries, Parser::NB_MAX_RELOCATIONS);

  stream_->setpos(offset_relocations);
  for (uint32_t i = 0; i < nb_entries; ++i) {
    if (!stream_->can_read<REL_T>()) {
      break;
    }
    const REL_T rel_hdr = stream_->read_conv<REL_T>();
    std::unique_ptr<Relocation> reloc{new Relocation{rel_hdr}};
    reloc->architecture_ = binary_->header_.machine_type();
    reloc->purpose(RELOCATION_PURPOSES::RELOC_PURPOSE_PLTGOT);

    const uint32_t idx  = static_cast<uint32_t>(rel_hdr.r_info >> shift);
    if (idx > 0 && idx < binary_->dynamic_symbols_.size()) {
      reloc->symbol_ = binary_->dynamic_symbols_[idx];
    }

    binary_->relocations_.push_back(reloc.release());
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

  static_assert(std::is_same<REL_T, Elf_Rel>::value ||
                std::is_same<REL_T, Elf_Rela>::value, "REL_T must be Elf_Rel || Elf_Rela");

  // A relocation section can reference two other sections: a symbol table,
  // identified by the sh_info section header entry, and a section to modify,
  // identified by the sh_link
  // BUT: in practice sh_info and sh_link are inverted
  Section* applies_to = nullptr;
  if (section.information() > 0 && section.information() < binary_->sections_.size()) {
    const size_t sh_info = section.information();
    applies_to = binary_->sections_[sh_info];
  }

  // FIXME: Use it
  // Section* section_associated = nullptr;
  // if (section.link() > 0 and section.link() < binary_->sections_.size()) {
  //   const size_t sh_link = section.link();
  //   section_associated = binary_->sections_[sh_link];
  // }

  const uint64_t offset_relocations = section.file_offset();
  const uint8_t shift = std::is_same<ELF_T, details::ELF32>::value ? 8 : 32;

  uint32_t nb_entries = static_cast<uint32_t>(section.size() / sizeof(REL_T));
  nb_entries = std::min<uint32_t>(nb_entries, Parser::NB_MAX_RELOCATIONS);

  std::map<RelocationKey, Relocation*> map;

  stream_->setpos(offset_relocations);
  for (uint32_t i = 0; i < nb_entries; ++i) {
    if (!stream_->can_read<REL_T>()) {
      break;
    }
    const REL_T rel_hdr = stream_->read_conv<REL_T>();

    std::unique_ptr<Relocation> reloc{new Relocation{rel_hdr}};
    reloc->architecture_ = binary_->header_.machine_type();
    reloc->section_      = applies_to;
    if (binary_->header().file_type() == ELF::E_TYPE::ET_REL &&
        binary_->segments().size() == 0) {
      reloc->purpose(RELOCATION_PURPOSES::RELOC_PURPOSE_OBJECT);
    }

    const uint32_t idx  = static_cast<uint32_t>(rel_hdr.r_info >> shift);
    if (idx > 0 && idx < binary_->dynamic_symbols_.size()) {
      reloc->symbol_ = binary_->dynamic_symbols_[idx];
    } else if (idx < binary_->static_symbols_.size()) {
      reloc->symbol_ = binary_->static_symbols_[idx];
    }

    RelocationKey k = {
        reloc->address(),
        reloc->type(),
        reloc->addend(),
        reloc->has_symbol() ? LIEF::Hash::hash(reloc->symbol()) : 0
    };

    if (map[k] == nullptr) {
        auto released = map[k] = reloc.release();
        binary_->relocations_.push_back(released);
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

  const uint64_t string_offset = get_dynamic_string_table();

  uint32_t next_symbol_offset = 0;

  for (uint32_t symbolCnt = 0; symbolCnt < nb_entries; ++symbolCnt) {
    if (!stream_->can_read<Elf_Verneed>(svr_offset + next_symbol_offset)) {
      break;
    }
    const Elf_Verneed header = stream_->peek_conv<Elf_Verneed>(svr_offset + next_symbol_offset);

    std::unique_ptr<SymbolVersionRequirement> symbol_version_requirement{new SymbolVersionRequirement{header}};
    if (string_offset != 0) {
      std::string name = stream_->peek_string_at(string_offset + header.vn_file);
      symbol_version_requirement->name(name);
    }

    const uint32_t nb_symbol_aux = header.vn_cnt;

    if (nb_symbol_aux > 0 && header.vn_aux > 0) {
      uint32_t next_aux_offset = 0;
      for (uint32_t j = 0; j < nb_symbol_aux; ++j) {
        if (!stream_->can_read<Elf_Vernaux>(svr_offset + next_symbol_offset + header.vn_aux + next_aux_offset)) {
          break;
        }
        const Elf_Vernaux aux_header =  stream_->peek_conv<Elf_Vernaux>(svr_offset + next_symbol_offset + header.vn_aux + next_aux_offset);

        std::unique_ptr<SymbolVersionAuxRequirement> svar{new SymbolVersionAuxRequirement{aux_header}};
        if (string_offset != 0) {
          svar->name(stream_->peek_string_at(string_offset + aux_header.vna_name));
        }

        symbol_version_requirement->symbol_version_aux_requirement_.push_back(svar.release());
        if (aux_header.vna_next == 0) break;
        next_aux_offset += aux_header.vna_next;
      }

      binary_->symbol_version_requirements_.push_back(symbol_version_requirement.release());
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
  for (SymbolVersionRequirement* svr : binary_->symbol_version_requirements_) {
    for (SymbolVersionAuxRequirement* svar : svr->symbol_version_aux_requirement_) {
      std::for_each(
          std::begin(binary_->symbol_version_table_),
          std::end(binary_->symbol_version_table_),
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

  const uint64_t string_offset = get_dynamic_string_table();
  uint32_t next_symbol_offset = 0;

  for (uint32_t i = 0; i < nb_entries; ++i) {
    if (!stream_->can_read<Elf_Verdef>(offset + next_symbol_offset)) {
      break;
    }
    const Elf_Verdef svd_header = stream_->peek_conv<Elf_Verdef>(offset + next_symbol_offset);

    std::unique_ptr<SymbolVersionDefinition> symbol_version_definition{new SymbolVersionDefinition{svd_header}};
    uint32_t nb_aux_symbols = svd_header.vd_cnt;
    uint32_t next_aux_offset = 0;
    for (uint32_t j = 0; j < nb_aux_symbols; ++j) {
      if (!stream_->can_read<Elf_Verdaux>(offset + next_symbol_offset + svd_header.vd_aux + next_aux_offset)) {
        break;
      }

      const Elf_Verdaux svda_header = stream_->peek_conv<Elf_Verdaux>(offset + next_symbol_offset + svd_header.vd_aux + next_aux_offset);

      if (string_offset != 0) {
        std::string name  = stream_->peek_string_at(string_offset + svda_header.vda_name);
        symbol_version_definition->symbol_version_aux_.push_back(new SymbolVersionAux{name});
      }

      // Additional check
      if (svda_header.vda_next == 0) break;

      next_aux_offset += svda_header.vda_next;
    }

    binary_->symbol_version_definition_.push_back(symbol_version_definition.release());

    // Additional check
    if (svd_header.vd_next == 0) break;

    next_symbol_offset += svd_header.vd_next;
  }

  // Associate Symbol Version with auxiliary symbol
  // We mask the 15th bit because it sets if this symbol is a hidden on or not
  // but we don't care
  for (SymbolVersionDefinition& svd : binary_->symbols_version_definition()) {
    for (SymbolVersionAux* sva : svd.symbol_version_aux_) {
      std::for_each(
          std::begin(binary_->symbol_version_table_),
          std::end(binary_->symbol_version_table_),
          [&sva, &svd] (SymbolVersion* sv)
          {
            if (svd.ndx() > 1 && (sv->value() & 0x7FFF) == svd.ndx() ) {
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
  static constexpr uint32_t MAX_NB_HASH    = 1000000;

  LIEF_DEBUG("== Parser symbol GNU hash ==");
  GnuHash gnuhash;
  gnuhash.c_ = sizeof(uint__) * 8;

  stream_->setpos(offset);

  std::unique_ptr<uint32_t[]> header = stream_->read_conv_array<uint32_t>(4, /* check */false);

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
      if (!stream_->can_read<uint__>()) {
        LIEF_ERR("Can't read maskwords #{:d}", i);
        break;
      }
      bloom_filters[i] = stream_->read_conv<uint__>();
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

  std::unique_ptr<uint32_t[]> hash_buckets = stream_->read_conv_array<uint32_t>(nbuckets, false);

  if (hash_buckets != nullptr) {
    buckets = {hash_buckets.get(), hash_buckets.get() + nbuckets};
  } else {
    LIEF_ERR("GNU Hash, hash_buckets corrupted");
  }

  gnuhash.buckets_ = std::move(buckets);

  const uint32_t dynsymcount = static_cast<uint32_t>(binary_->dynamic_symbols_.size());
  if (dynsymcount < symndx) {
    LIEF_ERR("GNU Hash, symndx corrupted");
  } else {
    uint32_t nb_hash = dynsymcount - symndx;
    if (nb_hash < MAX_NB_HASH) {
      std::vector<uint32_t> hashvalues;
      hashvalues.reserve(nb_hash);
      std::unique_ptr<uint32_t[]> hash_values = stream_->read_conv_array<uint32_t>(nb_hash, /* check */ false);
      if (hash_values == nullptr) {
        LIEF_ERR("Can't read hash table");
      } else {
        hashvalues = {hash_values.get(), hash_values.get() + nb_hash};
        gnuhash.hash_values_ = std::move(hashvalues);
      }
    } else {
      LIEF_ERR("The number of hash entries seems too high ({:d})", nb_hash);
    }
  }
  binary_->gnu_hash_ = std::move(gnuhash);

}

}
}
