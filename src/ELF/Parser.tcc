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
#include <cctype>
#include <memory>
#include <unordered_set>
#include "logging.hpp"

#include "LIEF/utils.hpp"
#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/Parser.hpp"
#include "LIEF/ELF/DynamicEntryFlags.hpp"
#include "LIEF/ELF/Relocation.hpp"
#include "LIEF/ELF/Segment.hpp"
#include "LIEF/ELF/Section.hpp"
#include "LIEF/ELF/GnuHash.hpp"
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
#include "LIEF/ELF/EnumToString.hpp"

#include "ELF/Structures.hpp"
#include "ELF/DataHandler/Handler.hpp"
#include "ELF/SizingInfo.hpp"

#include "Object.tcc"

namespace LIEF {
namespace ELF {
template<typename ELF_T>
ok_error_t Parser::parse_binary() {
  using Elf_Off  = typename ELF_T::Elf_Off;

  LIEF_DEBUG("Start parsing");
  // Parse header
  // ============
  auto res = parse_header<ELF_T>();
  if (!res) {
    LIEF_WARN("ELF Header parsed with errors");
  }

  // Parse Sections
  // ==============
  if (binary_->header_.section_headers_offset() > 0) {
    parse_sections<ELF_T>();
  } else {
    LIEF_WARN("The current binary doesn't have a section header");
  }

  // Parse segments
  // ==============
  if (binary_->header_.program_headers_offset() > 0) {
    LIEF_SW_START(sw);
    parse_segments<ELF_T>();
    LIEF_SW_END("segments parsed in {}", duration_cast<std::chrono::microseconds>(sw.elapsed()));
  } else {
    if (binary_->header().file_type() != E_TYPE::ET_REL) {
      LIEF_WARN("Binary doesn't have a program header");
    }
  }

  // Parse Dynamic elements
  // ======================

  // Find the dynamic Segment
  if (const Segment* seg_dyn = binary_->get(SEGMENT_TYPES::PT_DYNAMIC)) {
    const Elf_Off offset = seg_dyn->file_offset();
    const Elf_Off size   = seg_dyn->physical_size();

    parse_dynamic_entries<ELF_T>(offset, size);
    binary_->sizing_info_->dynamic = size;
  }


  // Parse dynamic symbols
  // =====================
  {
    DynamicEntry* dt_symtab = binary_->get(DYNAMIC_TAGS::DT_SYMTAB);
    DynamicEntry* dt_syment = binary_->get(DYNAMIC_TAGS::DT_SYMENT);

    if (dt_symtab != nullptr && dt_syment != nullptr) {
      const uint64_t virtual_address = dt_symtab->value();
      if (auto res = binary_->virtual_address_to_offset(virtual_address)) {
        parse_dynamic_symbols<ELF_T>(*res);
      } else {
        LIEF_WARN("Can't convert DT_SYMTAB.virtual_address into an offset (0x{:x})", virtual_address);
      }
    }
  }

  // Parse dynamic relocations
  // =========================

  // RELA
  // ----
  {
    DynamicEntry* dt_rela   = binary_->get(DYNAMIC_TAGS::DT_RELA);
    DynamicEntry* dt_relasz = binary_->get(DYNAMIC_TAGS::DT_RELASZ);

    if (dt_rela != nullptr && dt_relasz != nullptr) {
      const uint64_t virtual_address = dt_rela->value();
      const uint64_t size            = dt_relasz->value();
      if (auto res = binary_->virtual_address_to_offset(virtual_address)) {
        parse_dynamic_relocations<ELF_T, typename ELF_T::Elf_Rela>(*res, size);
        binary_->sizing_info_->rela = size;
      } else {
        LIEF_WARN("Can't convert DT_RELA.virtual_address into an offset (0x{:x})", virtual_address);
      }
    }
  }


  // REL
  // ---
  {
    DynamicEntry* dt_rel   = binary_->get(DYNAMIC_TAGS::DT_REL);
    DynamicEntry* dt_relsz = binary_->get(DYNAMIC_TAGS::DT_RELSZ);

    if (dt_rel != nullptr && dt_relsz != nullptr) {
      const uint64_t virtual_address = dt_rel->value();
      const uint64_t size            = dt_relsz->value();
      if (auto res = binary_->virtual_address_to_offset(virtual_address)) {
        parse_dynamic_relocations<ELF_T, typename ELF_T::Elf_Rel>(*res, size);
        binary_->sizing_info_->rela = size;
      } else {
        LIEF_WARN("Can't convert DT_REL.virtual_address into an offset (0x{:x})", virtual_address);
      }
    }
  }

  // Parse PLT/GOT Relocations
  // ==========================
  {
    DynamicEntry* dt_jmprel   = binary_->get(DYNAMIC_TAGS::DT_JMPREL);
    DynamicEntry* dt_pltrelsz = binary_->get(DYNAMIC_TAGS::DT_PLTRELSZ);

    if (dt_jmprel != nullptr && dt_pltrelsz != nullptr) {
      const uint64_t virtual_address = dt_jmprel->value();
      const uint64_t size            = dt_pltrelsz->value();
      DynamicEntry* dt_pltrel        = binary_->get(DYNAMIC_TAGS::DT_PLTREL);
      DYNAMIC_TAGS type;
      if (dt_pltrel != nullptr) {
        type = static_cast<DYNAMIC_TAGS>(dt_pltrel->value());
      } else {
        // Try to guess: We assume that on ELF64 -> DT_RELA and on ELF32 -> DT_REL
        if (std::is_same<ELF_T, details::ELF64>::value) {
          type = DYNAMIC_TAGS::DT_RELA;
        } else {
          type = DYNAMIC_TAGS::DT_REL;
        }
      }

      if (auto res = binary_->virtual_address_to_offset(virtual_address)) {
        auto parsing_result = type == DYNAMIC_TAGS::DT_RELA ?
                              parse_pltgot_relocations<ELF_T, typename ELF_T::Elf_Rela>(*res, size) :
                              parse_pltgot_relocations<ELF_T, typename ELF_T::Elf_Rel>(*res, size);
        binary_->sizing_info_->jmprel = size;
      } else {
        LIEF_WARN("Can't convert DT_JMPREL.virtual_address into an offset (0x{:x})", virtual_address);
      }
    }
  }

  // Parse Symbol Version
  // ====================
  if (DynamicEntry* dt_versym = binary_->get(DYNAMIC_TAGS::DT_VERSYM)) {
    const uint64_t virtual_address = dt_versym->value();
    if (auto res = binary_->virtual_address_to_offset(virtual_address)) {
      parse_symbol_version(*res);
      binary_->sizing_info_->versym = binary_->dynamic_symbols_.size() * sizeof(uint16_t);
    } else {
      LIEF_WARN("Can't convert DT_VERSYM.virtual_address into an offset (0x{:x})", virtual_address);
    }
  }


  // Parse Symbol Version Requirement
  // ================================
  {
    DynamicEntry* dt_verneed     = binary_->get(DYNAMIC_TAGS::DT_VERNEED);
    DynamicEntry* dt_verneed_num = binary_->get(DYNAMIC_TAGS::DT_VERNEEDNUM);

    if (dt_verneed != nullptr && dt_verneed_num != nullptr) {
      const uint64_t virtual_address = dt_verneed->value();
      const uint32_t nb_entries = std::min(Parser::NB_MAX_SYMBOLS,
                                           static_cast<uint32_t>(dt_verneed_num->value()));

      if (auto res = binary_->virtual_address_to_offset(virtual_address)) {
        parse_symbol_version_requirement<ELF_T>(*res, nb_entries);
      } else {
        LIEF_WARN("Can't convert DT_VERNEED.virtual_address into an offset (0x{:x})", virtual_address);
      }
    }
  }

  // Parse Symbol Version Definition
  // ===============================
  {
    DynamicEntry* dt_verdef     = binary_->get(DYNAMIC_TAGS::DT_VERDEF);
    DynamicEntry* dt_verdef_num = binary_->get(DYNAMIC_TAGS::DT_VERDEFNUM);
    if (dt_verdef != nullptr && dt_verdef_num != nullptr) {
      const uint64_t virtual_address = dt_verdef->value();
      const auto size                = static_cast<uint32_t>(dt_verdef_num->value());

      if (auto res = binary_->virtual_address_to_offset(virtual_address)) {
        parse_symbol_version_definition<ELF_T>(*res, size);
      } else {
        LIEF_WARN("Can't convert DT_VERDEF.virtual_address into an offset (0x{:x})", virtual_address);
      }
    }
  }


  // Parse static symbols
  // ====================
  if (const Section* sec_symbtab = binary_->get(ELF_SECTION_TYPES::SHT_SYMTAB)) {
    auto nb_entries = static_cast<uint32_t>((sec_symbtab->size() / sizeof(typename ELF_T::Elf_Sym)));
    nb_entries = std::min(nb_entries, Parser::NB_MAX_SYMBOLS);

    if (sec_symbtab->link() == 0 || sec_symbtab->link() >= binary_->sections_.size()) {
      LIEF_WARN("section->link() is not valid !");
    } else {
      // We should have:
      // nb_entries == section->information())
      // but lots of compiler not respect this rule
      parse_static_symbols<ELF_T>(sec_symbtab->file_offset(), nb_entries,
                                  *binary_->sections_[sec_symbtab->link()]);
    }
  }


  // Parse Symbols's hash
  // ====================
  if (DynamicEntry* dt_hash = binary_->get(DYNAMIC_TAGS::DT_HASH)) {
    if (auto res = binary_->virtual_address_to_offset(dt_hash->value())) {
      parse_symbol_sysv_hash(*res);
    } else {
      LIEF_WARN("Can't convert DT_HASH.virtual_address into an offset (0x{:x})", dt_hash->value());
    }
  }


  if (DynamicEntry* dt_gnu_hash = binary_->get(DYNAMIC_TAGS::DT_GNU_HASH)) {
    if (auto res = binary_->virtual_address_to_offset(dt_gnu_hash->value())) {
      parse_symbol_gnu_hash<ELF_T>(*res);
    } else {
      LIEF_WARN("Can't convert DT_GNU_HASH.virtual_address into an offset (0x{:x})", dt_gnu_hash->value());
    }
  }

  // Parse Note segment
  // ==================
  for (const Segment& segment : binary_->segments()) {
    if (segment.type() != SEGMENT_TYPES::PT_NOTE) {
      continue;
    }

    const uint64_t va = segment.virtual_address();
    if (auto res = binary_->virtual_address_to_offset(va)) {
      parse_notes(*res, segment.physical_size());
    } else {
      LIEF_WARN("Can't convert PT_NOTE.virtual_address into an offset (0x{:x})", va);
    }
  }

  // Parse Note Sections
  // ===================
  for (const Section& section : binary_->sections()) {
    if (section.type() != ELF_SECTION_TYPES::SHT_NOTE) {
      continue;
    }

    parse_notes(section.offset(), section.size());
  }

  // Try to parse using sections
  // If we don't have any relocations, we parse all relocation sections
  // otherwise, only the non-allocated sections to avoid parsing dynamic
  // relocations (or plt relocations) twice.
  bool skip_allocated_sections = !binary_->relocations_.empty();
  for (const Section& section : binary_->sections()) {
    if (skip_allocated_sections && section.has(ELF_SECTION_FLAGS::SHF_ALLOC)){
      continue;
    }
    if (section.type() == ELF_SECTION_TYPES::SHT_REL) {
      parse_section_relocations<ELF_T, typename ELF_T::Elf_Rel>(section);
    }
    else if (section.type() == ELF_SECTION_TYPES::SHT_RELA) {
      parse_section_relocations<ELF_T, typename ELF_T::Elf_Rela>(section);
    }
  }

  link_symbol_version();
  parse_overlay();
  return ok();
}


template<typename ELF_T>
ok_error_t Parser::parse_header() {
  using Elf_Half = typename ELF_T::Elf_Half;
  using Elf_Word = typename ELF_T::Elf_Word;
  using Elf_Addr = typename ELF_T::Elf_Addr;
  using Elf_Off  = typename ELF_T::Elf_Off;

  LIEF_DEBUG("[+] Parsing Header");
  stream_->setpos(0);
  if (auto res = stream_->read<Header::identity_t>()) {
    binary_->header_.identity_ = *res;
  } else {
    LIEF_ERR("Can't parse Elf_Ehdr.e_ident");
    return make_error_code(lief_errors::read_error);
  }

  if (auto res = stream_->read_conv<Elf_Half>()) {
    binary_->header_.file_type_ = static_cast<E_TYPE>(*res);
  } else {
    LIEF_ERR("Can't parse Elf_Ehdr.e_type");
    return make_error_code(lief_errors::read_error);
  }

  if (auto res = stream_->read_conv<Elf_Half>()) {
    binary_->header_.machine_type_ = static_cast<ARCH>(*res);
  } else {
    LIEF_ERR("Can't parse Elf_Ehdr.e_machine");
    return make_error_code(lief_errors::read_error);
  }

  if (auto res = stream_->read_conv<Elf_Word>()) {
    binary_->header_.object_file_version_ = static_cast<VERSION>(*res);
  } else {
    LIEF_ERR("Can't parse Elf_Ehdr.e_version");
    return make_error_code(lief_errors::read_error);
  }

  if (auto res = stream_->read_conv<Elf_Addr>()) {
    binary_->header_.entrypoint_ = *res;
  } else {
    LIEF_ERR("Can't parse Elf_Ehdr.e_entry");
    return make_error_code(lief_errors::read_error);
  }

  if (auto res = stream_->read_conv<Elf_Off>()) {
    binary_->header_.program_headers_offset_ = *res;
  } else {
    LIEF_ERR("Can't parse Elf_Ehdr.e_phoff");
    return make_error_code(lief_errors::read_error);
  }

  if (auto res = stream_->read_conv<Elf_Off>()) {
    binary_->header_.section_headers_offset_ = *res;
  } else {
    LIEF_ERR("Can't parse Elf_Ehdr.e_shoff");
    return make_error_code(lief_errors::read_error);
  }

  if (auto res = stream_->read_conv<Elf_Word>()) {
    binary_->header_.processor_flags_ = *res;
  } else {
    LIEF_ERR("Can't parse Elf_Ehdr.e_flags");
    return make_error_code(lief_errors::read_error);
  }

  if (auto res = stream_->read_conv<Elf_Half>()) {
    binary_->header_.header_size_ = *res;
  } else {
    LIEF_ERR("Can't parse Elf_Ehdr.e_ehsize");
    return make_error_code(lief_errors::read_error);
  }

  if (auto res = stream_->read_conv<Elf_Half>()) {
    binary_->header_.program_header_size_ = *res;
  } else {
    LIEF_ERR("Can't parse Elf_Ehdr.e_phentsize");
    return make_error_code(lief_errors::read_error);
  }

  if (auto res = stream_->read_conv<Elf_Half>()) {
    binary_->header_.numberof_segments_ = *res;
  } else {
    if (auto res = stream_->read_conv<uint8_t>()) {
      binary_->header_.numberof_segments_ = *res;
    } else {
      LIEF_ERR("Can't parse Elf_Ehdr.e_phnum");
      return make_error_code(lief_errors::read_error);
    }
  }

  if (auto res = stream_->read_conv<Elf_Half>()) {
    binary_->header_.section_header_size_ = *res;
  } else {
    LIEF_ERR("Can't parse Elf_Ehdr.e_shentsize");
    return make_error_code(lief_errors::read_error);
  }

  if (auto res = stream_->read_conv<Elf_Half>()) {
    binary_->header_.numberof_sections_ = *res;
  } else {
    LIEF_ERR("Can't parse Elf_Ehdr.e_shnum");
    return make_error_code(lief_errors::read_error);
  }

  if (auto res = stream_->read_conv<Elf_Half>()) {
    binary_->header_.section_string_table_idx_ = *res;
  } else {
    LIEF_ERR("Can't parse Elf_Ehdr.e_shstrndx");
    return make_error_code(lief_errors::read_error);
  }

  return ok();
}


template<typename ELF_T>
result<uint32_t> Parser::get_numberof_dynamic_symbols(DYNSYM_COUNT_METHODS mtd) const {

  switch(mtd) {
    case DYNSYM_COUNT_METHODS::COUNT_HASH:        return nb_dynsym_hash<ELF_T>();
    case DYNSYM_COUNT_METHODS::COUNT_SECTION:     return nb_dynsym_section<ELF_T>();
    case DYNSYM_COUNT_METHODS::COUNT_RELOCATIONS: return nb_dynsym_relocations<ELF_T>();

    case DYNSYM_COUNT_METHODS::COUNT_AUTO:
    default:
      {
        uint32_t nb_dynsym     = 0;
        uint32_t nb_dynsym_tmp = 0;

        auto res = get_numberof_dynamic_symbols<ELF_T>(DYNSYM_COUNT_METHODS::COUNT_RELOCATIONS);
        if (res) {
          nb_dynsym = res.value();
        }
        res = get_numberof_dynamic_symbols<ELF_T>(DYNSYM_COUNT_METHODS::COUNT_SECTION);
        if (res) {
          nb_dynsym_tmp = res.value();
        }

        if (nb_dynsym_tmp < Parser::NB_MAX_SYMBOLS &&
            nb_dynsym_tmp > nb_dynsym              &&
            (nb_dynsym_tmp - nb_dynsym) < Parser::DELTA_NB_SYMBOLS)
        {
          nb_dynsym = nb_dynsym_tmp;
        }

        res = get_numberof_dynamic_symbols<ELF_T>(DYNSYM_COUNT_METHODS::COUNT_HASH);
        if (!res) {
          // Fail to get number of symbols from the hash table
          return nb_dynsym;
        }

        nb_dynsym_tmp = res.value();
        if (nb_dynsym_tmp < Parser::NB_MAX_SYMBOLS &&
            nb_dynsym_tmp > nb_dynsym              &&
            (nb_dynsym_tmp - nb_dynsym) < Parser::DELTA_NB_SYMBOLS)
        {
          nb_dynsym = nb_dynsym_tmp;
        }
        return nb_dynsym;
      }
  }
}

template<typename ELF_T>
result<uint32_t> Parser::nb_dynsym_relocations() const {
  using rela_t = typename ELF_T::Elf_Rela;
  using rel_t  = typename ELF_T::Elf_Rel;
  uint32_t nb_symbols = 0;

  // Dynamic Relocations
  // ===================

  // RELA
  // ----
  DynamicEntry* dt_rela   = binary_->get(DYNAMIC_TAGS::DT_RELA);
  DynamicEntry* dt_relasz = binary_->get(DYNAMIC_TAGS::DT_RELASZ);
  if (dt_rela != nullptr && dt_relasz != nullptr) {
    const uint64_t virtual_address = dt_rela->value();
    const uint64_t size            = dt_relasz->value();
    if (auto res = binary_->virtual_address_to_offset(virtual_address)) {
      nb_symbols = std::max(nb_symbols, max_relocation_index<ELF_T, rela_t>(*res, size));
    }
  }


  // REL
  // ---
  DynamicEntry* dt_rel   = binary_->get(DYNAMIC_TAGS::DT_REL);
  DynamicEntry* dt_relsz = binary_->get(DYNAMIC_TAGS::DT_RELSZ);

  if (dt_rel != nullptr && dt_relsz != nullptr) {
    const uint64_t virtual_address = dt_rel->value();
    const uint64_t size            = dt_relsz->value();
    if (auto res = binary_->virtual_address_to_offset(virtual_address)) {
      nb_symbols = std::max(nb_symbols, max_relocation_index<ELF_T, rel_t>(*res, size));
    }
  }

  // Parse PLT/GOT Relocations
  // ==========================

  DynamicEntry* dt_jmprel   = binary_->get(DYNAMIC_TAGS::DT_JMPREL);
  DynamicEntry* dt_pltrelsz = binary_->get(DYNAMIC_TAGS::DT_PLTRELSZ);
  if (dt_jmprel != nullptr && dt_pltrelsz != nullptr) {
    const uint64_t virtual_address = dt_jmprel->value();
    const uint64_t size            = dt_pltrelsz->value();
    DynamicEntry* dt_pltrel        = binary_->get(DYNAMIC_TAGS::DT_PLTREL);
    DYNAMIC_TAGS type;
    if (dt_pltrel != nullptr) {
      type = static_cast<DYNAMIC_TAGS>(dt_pltrel->value());
    } else {
      // Try to guess: We assume that on ELF64 -> DT_RELA and on ELF32 -> DT_REL
      if (std::is_same<ELF_T, details::ELF64>::value) {
        type = DYNAMIC_TAGS::DT_RELA;
      } else {
        type = DYNAMIC_TAGS::DT_REL;
      }
    }
    if (auto res = binary_->virtual_address_to_offset(virtual_address)) {
      if (type == DYNAMIC_TAGS::DT_RELA) {
        nb_symbols = std::max(nb_symbols, max_relocation_index<ELF_T, rela_t>(*res, size));
      } else {
        nb_symbols = std::max(nb_symbols, max_relocation_index<ELF_T, rel_t>(*res, size));
      }
    }
  }

  return nb_symbols;
}

template<typename ELF_T, typename REL_T>
uint32_t Parser::max_relocation_index(uint64_t relocations_offset, uint64_t size) const {
  static_assert(std::is_same<REL_T, typename ELF_T::Elf_Rel>::value ||
                std::is_same<REL_T, typename ELF_T::Elf_Rela>::value, "REL_T must be Elf_Rel || Elf_Rela");

  const uint8_t shift = std::is_same<ELF_T, details::ELF32>::value ? 8 : 32;

  const auto nb_entries = static_cast<uint32_t>(size / sizeof(REL_T));

  uint32_t idx = 0;
  stream_->setpos(relocations_offset);
  for (uint32_t i = 0; i < nb_entries; ++i) {
    auto reloc_entry = stream_->read_conv<REL_T>();
    if (!reloc_entry) {
      break;
    }
    idx = std::max(idx, static_cast<uint32_t>(reloc_entry->r_info >> shift));
  }
  return idx + 1;
} // max_relocation_index



template<typename ELF_T>
result<uint32_t> Parser::nb_dynsym_section() const {
  using Elf_Sym = typename ELF_T::Elf_Sym;
  using Elf_Off = typename ELF_T::Elf_Off;
  Section* dynsym_sec = binary_->get(ELF_SECTION_TYPES::SHT_DYNSYM);

  if (dynsym_sec == nullptr) {
    return 0;
  }

  const Elf_Off section_size = dynsym_sec->size();
  const auto nb_symbols = static_cast<uint32_t>((section_size / sizeof(Elf_Sym)));
  return nb_symbols;
}

template<typename ELF_T>
result<uint32_t> Parser::nb_dynsym_hash() const {

  if (binary_->has(DYNAMIC_TAGS::DT_HASH)) {
    return nb_dynsym_sysv_hash<ELF_T>();
  }

  if (binary_->has(DYNAMIC_TAGS::DT_GNU_HASH)) {
    return nb_dynsym_gnu_hash<ELF_T>();
  }

  return 0;
}


template<typename ELF_T>
result<uint32_t> Parser::nb_dynsym_sysv_hash() const {
  using Elf_Off  = typename ELF_T::Elf_Off;

  const DynamicEntry* dyn_hash = binary_->get(DYNAMIC_TAGS::DT_HASH);
  if (dyn_hash == nullptr) {
    LIEF_ERR("Can't find DT_GNU_HASH");
    return make_error_code(lief_errors::not_found);
  }
  Elf_Off sysv_hash_offset = 0;
  if (auto res = binary_->virtual_address_to_offset(dyn_hash->value())) {
    sysv_hash_offset = *res;
  } else {
    return res.error();
  }

  // From the doc: 'so nchain should equal the number of symbol table entries.'
  stream_->setpos(sysv_hash_offset + sizeof(uint32_t));
  auto nb_symbols = stream_->read_conv<uint32_t>();
  if (nb_symbols) {
    return nb_symbols;
  }

  return 0;
}

template<typename ELF_T>
result<uint32_t> Parser::nb_dynsym_gnu_hash() const {
  using uint__ = typename ELF_T::uint;
  using Elf_Off  = typename ELF_T::Elf_Off;

  const DynamicEntry* dyn_hash = binary_->get(DYNAMIC_TAGS::DT_GNU_HASH);
  if (dyn_hash == nullptr) {
    LIEF_ERR("Can't find DT_GNU_HASH");
    return make_error_code(lief_errors::not_found);
  }
  Elf_Off gnu_hash_offset = 0;

  if (auto res = binary_->virtual_address_to_offset(dyn_hash->value())) {
    gnu_hash_offset = *res;
  } else {
    return res.error();
  }

  stream_->setpos(gnu_hash_offset);
  const auto res_nbuckets = stream_->read_conv<uint32_t>();
  if (!res_nbuckets) {
    return 0;
  }

  const auto res_symndx = stream_->read_conv<uint32_t>();
  if (!res_symndx) {
    return 0;
  }

  const auto res_maskwords = stream_->read_conv<uint32_t>();
  if (!res_maskwords) {
    return 0;
  }

  const auto nbuckets  = *res_nbuckets;
  const auto symndx    = *res_symndx;
  const auto maskwords = *res_maskwords;

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
    auto bucket = stream_->read_conv<uint32_t>();
    if (!bucket) {
      break;
    }
    if (*bucket > max_bucket) {
      max_bucket = *bucket;
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
    hash_value = *stream_->read_conv<uint32_t>();

    nsyms++;
  } while ((hash_value & 1) == 0); // "It is set to 1 when a symbol is the last symbol in a given hash bucket"

  return max_bucket + nsyms;
}

template<typename ELF_T>
ok_error_t Parser::parse_sections() {
  using Elf_Shdr = typename ELF_T::Elf_Shdr;

  using Elf_Off  = typename ELF_T::Elf_Off;
  LIEF_DEBUG("Parsing Section");

  const Elf_Off shdr_offset = binary_->header_.section_headers_offset();
  const auto numberof_sections = binary_->header_.numberof_sections();

  stream_->setpos(shdr_offset);
  std::unordered_map<Section*, size_t> sections_names;
  DataHandler::Handler& handler = *binary_->datahandler_;
  for (size_t i = 0; i < numberof_sections; ++i) {
    LIEF_DEBUG("  Elf_Shdr#{:02d}.offset: 0x{:x} ", i, stream_->pos());
    const auto shdr = stream_->read_conv<Elf_Shdr>();
    if (!shdr) {
      LIEF_ERR("  Can't parse section #{:02d}", i);
      break;
    }

    auto section = std::make_unique<Section>(*shdr);
    section->datahandler_ = binary_->datahandler_.get();

    const uint64_t section_start = section->file_offset();
    const uint64_t section_end   = section_start + section->size();
    bool access_content = true;
    if (section_start > stream_->size() || section_end > stream_->size()) {
      access_content = false;
      if (section->type() != ELF_SECTION_TYPES::SHT_NOBITS) {
        LIEF_WARN("Can't access the content of section #{}", i);
      }
    }

    if (section->size() == 0 && section->file_offset() > 0 && access_content) {
      // Even if the size is 0, it is worth creating the node
      handler.create(section->file_offset(), 0, DataHandler::Node::SECTION);
    }

    // Only if it contains data (with bits)
    if (section->size() > 0 && access_content) {
      uint64_t read_size = section->size();
      if (read_size > Parser::MAX_SECTION_SIZE) {
        LIEF_WARN("Section #{} is {} bytes large. Only the first {} bytes will be taken into account",
                  i, read_size, Parser::MAX_SECTION_SIZE);
        read_size = Parser::MAX_SECTION_SIZE;
      }

      handler.create(section->file_offset(), read_size,
                     DataHandler::Node::SECTION);

      const Elf_Off offset_to_content = section->file_offset();
      auto alloc = binary_->datahandler_->reserve(section->file_offset(), read_size);
      if (!alloc) {
        LIEF_ERR("Can't allocate memory");
        break;
      }

      /* The DataHandlerStream interface references ELF data that are
       * located in the ELF::DataHandler. Therefore, we can skip reading
       * the data since they are already present in the data handler.
       * This optimization saves memory (which is also performed in parse_segments<>(...))
       */
      if (stream_->type() != BinaryStream::STREAM_TYPE::ELF_DATA_HANDLER) {
        std::vector<uint8_t> sec_content;
        if (!stream_->peek_data(sec_content, offset_to_content, read_size)) {
          if (section->type() != ELF_SECTION_TYPES::SHT_NOBITS) {
            LIEF_WARN("  Unable to get content of section #{:d}", i);
          }
        } else {
          section->content(std::move(sec_content));
        }
      }
    }
    sections_names[section.get()] = shdr->sh_name;
    binary_->sections_.push_back(std::move(section));
  }

  LIEF_DEBUG("    Parse section names");
  // Parse name
  if (binary_->header_.section_name_table_idx() >= binary_->sections_.size()) {
    LIEF_WARN("The .shstr index is out of range of the section table");
    return ok();
  }

  const size_t section_string_index = binary_->header_.section_name_table_idx();
  const std::unique_ptr<Section>& string_section = binary_->sections_[section_string_index];
  for (std::unique_ptr<Section>& section : binary_->sections_) {
    const auto it_name_idx = sections_names.find(section.get());
    if (it_name_idx == std::end(sections_names)) {
      LIEF_WARN("Missing name_idx for section at offset 0x{:x}", section->file_offset());
      continue;
    }
    const size_t name_offset = it_name_idx->second;
    auto name = stream_->peek_string_at(string_section->file_offset() + name_offset);
    if (!name) {
      LIEF_ERR("Can't read section name for section 0x{:x}", section->file_offset());
      break;
    }
    section->name(*name);
  }
  return ok();
}

template<typename ELF_T>
ok_error_t Parser::parse_segments() {
  using Elf_Phdr = typename ELF_T::Elf_Phdr;
  using Elf_Off  = typename ELF_T::Elf_Off;

  LIEF_DEBUG("== Parse Segments ==");
  const Header& hdr = binary_->header();
  const Elf_Off segment_headers_offset = hdr.program_headers_offset();
  const auto nbof_segments = std::min<uint32_t>(hdr.numberof_segments(), Parser::NB_MAX_SEGMENTS);

  stream_->setpos(segment_headers_offset);

  for (size_t i = 0; i < nbof_segments; ++i) {
    const auto elf_phdr = stream_->read_conv<Elf_Phdr>();
    if (!elf_phdr) {
      LIEF_ERR("Can't parse segement #{:d}", i);
      break;
    }

    auto segment = std::make_unique<Segment>(*elf_phdr);
    segment->datahandler_ = binary_->datahandler_.get();

    if (0 < segment->physical_size() && segment->physical_size() < Parser::MAX_SEGMENT_SIZE) {
      uint64_t read_size = segment->physical_size();
      if (read_size > Parser::MAX_SEGMENT_SIZE) {
        LIEF_WARN("Segment #{} is {} bytes large. Only the first {} bytes will be taken into account",
                  i, read_size, Parser::MAX_SEGMENT_SIZE);
        read_size = Parser::MAX_SEGMENT_SIZE;
      }
      if (read_size > stream_->size()) {
        LIEF_WARN("Segment #{} has a physical size larger than the current stream size ({} > {}). "
                  "The content will be truncated with the stream size.",
                  i, read_size, stream_->size());
        read_size = stream_->size();
      }

      segment->datahandler_->create(segment->file_offset(), read_size,
                                    DataHandler::Node::SEGMENT);
      segment->handler_size_ = read_size;

      if (segment->file_offset() > stream_->size() || (segment->file_offset() + read_size) > stream_->size()) {
        LIEF_WARN("Segment #{} has a corrupted file offset (0x{:x}) ", i, segment->file_offset());
        break;
      }
      const Elf_Off offset_to_content = segment->file_offset();
      auto alloc = binary_->datahandler_->reserve(segment->file_offset(), read_size);
      if (!alloc) {
        LIEF_ERR("Can't allocate memory");
        break;
      }
      /* The DataHandlerStream interface references ELF data that are
       * located in the ELF::DataHandler. Therefore, we can skip reading
       * the data since they are already present in the data handler.
       * This optimization saves memory (which is also performed in parse_sections<>(...))
       */
      if (stream_->type() != BinaryStream::STREAM_TYPE::ELF_DATA_HANDLER) {
        std::vector<uint8_t> seg_content;
        if (stream_->peek_data(seg_content, offset_to_content, read_size)) {
          segment->content(std::move(seg_content));
        } else {
          LIEF_ERR("Unable to get the content of segment #{:d}", i);
        }
      }

      if (segment->type() == SEGMENT_TYPES::PT_INTERP) {
        auto interpreter = stream_->peek_string_at(offset_to_content, read_size);
        if (!interpreter) {
          LIEF_ERR("Can't read the interpreter string");
        } else {
          binary_->interpreter_ = *interpreter;
          binary_->sizing_info_->interpreter = read_size;
        }
      }
    } else {
      segment->handler_size_ = segment->physical_size();
      segment->datahandler_->create(segment->file_offset(), segment->physical_size(),
                                    DataHandler::Node::SEGMENT);
    }

    for (std::unique_ptr<Section>& section : binary_->sections_) {
      if (check_section_in_segment(*section, *segment.get())) {
        section->segments_.push_back(segment.get());
        segment->sections_.push_back(section.get());
      }
    }
    binary_->segments_.push_back(std::move(segment));
  }
  return ok();
}



template<typename ELF_T, typename REL_T>
ok_error_t Parser::parse_dynamic_relocations(uint64_t relocations_offset, uint64_t size) {
  static_assert(std::is_same<REL_T, typename ELF_T::Elf_Rel>::value ||
                std::is_same<REL_T, typename ELF_T::Elf_Rela>::value, "REL_T must be Elf_Rel || Elf_Rela");
  LIEF_DEBUG("== Parsing dynamic relocations ==");

  // Already parsed
  if (binary_->dynamic_relocations().size() > 0) {
    return ok();
  }

  const uint8_t shift = std::is_same<ELF_T, details::ELF32>::value ? 8 : 32;

  auto nb_entries = static_cast<uint32_t>(size / sizeof(REL_T));

  nb_entries = std::min<uint32_t>(nb_entries, Parser::NB_MAX_RELOCATIONS);

  stream_->setpos(relocations_offset);
  const ARCH arch = binary_->header().machine_type();
  for (uint32_t i = 0; i < nb_entries; ++i) {
    const auto raw_reloc = stream_->read_conv<REL_T>();
    if (!raw_reloc) {
      break;
    }
    auto reloc = std::make_unique<Relocation>(*raw_reloc);
    reloc->purpose(RELOCATION_PURPOSES::RELOC_PURPOSE_DYNAMIC);
    reloc->architecture_ = arch;

    const auto idx = static_cast<uint32_t>(raw_reloc->r_info >> shift);

    if (idx < binary_->dynamic_symbols_.size()) {
      reloc->symbol_ = binary_->dynamic_symbols_[idx].get();
    } else {
      LIEF_WARN("Unable to find the symbol associated with the relocation (idx: {}) {}", idx, *reloc);
    }

    binary_->relocations_.push_back(std::move(reloc));
  }
  return ok();
} // build_dynamic_reclocations



template<typename ELF_T>
ok_error_t Parser::parse_static_symbols(uint64_t offset, uint32_t nb_symbols,
                                        const Section& string_section) {

  using Elf_Sym = typename ELF_T::Elf_Sym;
  LIEF_DEBUG("== Parsing static symbols ==");

  stream_->setpos(offset);
  for (uint32_t i = 0; i < nb_symbols; ++i) {
    const auto raw_sym = stream_->read_conv<Elf_Sym>();
    if (!raw_sym) {
      break;
    }
    auto symbol = std::make_unique<Symbol>(*raw_sym);
    auto symbol_name = stream_->peek_string_at(string_section.file_offset() + raw_sym->st_name);
    if (symbol_name) {
      symbol->name(std::move(*symbol_name));
    } else {
      LIEF_ERR("Can't read the symbol's name for symbol #{}", i);
    }
    binary_->static_symbols_.push_back(std::move(symbol));
  }
  return ok();
} // build_static_symbols


template<typename ELF_T>
ok_error_t Parser::parse_dynamic_symbols(uint64_t offset) {
  using Elf_Sym = typename ELF_T::Elf_Sym;
  using Elf_Off = typename ELF_T::Elf_Off;

  LIEF_DEBUG("== Parsing dynamics symbols ==");

  auto res = get_numberof_dynamic_symbols<ELF_T>(count_mtd_);
  if (!res) {
    LIEF_ERR("Fail to get the number of dynamic symbols with the current counting method");
    return make_error_code(lief_errors::parsing_error);
  }

  const uint32_t nb_symbols = res.value();

  const Elf_Off dynamic_symbols_offset = offset;
  const Elf_Off string_offset          = get_dynamic_string_table();

  LIEF_DEBUG("    - Number of symbols counted: {:d}", nb_symbols);
  LIEF_DEBUG("    - Table Offset:              0x{:x}", dynamic_symbols_offset);
  LIEF_DEBUG("    - String Table Offset:       0x{:x}", string_offset);

  if (string_offset == 0) {
    LIEF_WARN("Unable to find the .dynstr section");
    return make_error_code(lief_errors::parsing_error);
  }

  stream_->setpos(dynamic_symbols_offset);
  for (size_t i = 0; i < nb_symbols; ++i) {
    const auto symbol_header = stream_->read_conv<Elf_Sym>();
    if (!symbol_header) {
      LIEF_DEBUG("Break on symbol #{:d}", i);
      break;
    }
    auto symbol = std::make_unique<Symbol>(*symbol_header);

    if (symbol_header->st_name > 0) {
      auto name = stream_->peek_string_at(string_offset + symbol_header->st_name);
      if (!name) {
        break;
      }

      if (name->empty() && i > 0) {
        LIEF_DEBUG("Symbol's name #{:d} is empty!", i);
      }

      symbol->name(std::move(*name));
    }
    binary_->dynamic_symbols_.push_back(std::move(symbol));
  }
  binary_->sizing_info_->dynsym = binary_->dynamic_symbols_.size() * sizeof(Elf_Sym);
  if (const auto* dt_strsz = binary_->get(DYNAMIC_TAGS::DT_STRSZ)) {
    binary_->sizing_info_->dynstr = dt_strsz->value();
  }
  return ok();
} // build_dynamic_sybols


template<typename ELF_T>
ok_error_t Parser::parse_dynamic_entries(uint64_t offset, uint64_t size) {
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
    const auto res_entry = stream_->read_conv<Elf_Dyn>();
    if (!res_entry) {
      break;
    }
    const auto entry = *res_entry;

    std::unique_ptr<DynamicEntry> dynamic_entry;

    switch (static_cast<DYNAMIC_TAGS>(entry.d_tag)) {
      case DYNAMIC_TAGS::DT_NEEDED :
        {
          dynamic_entry = std::make_unique<DynamicEntryLibrary>(entry);
          auto library_name = stream_->peek_string_at(dynamic_string_offset + dynamic_entry->value());
          if (!library_name) {
            LIEF_ERR("Can't read library name for DT_NEEDED entry");
            break;
          }
          dynamic_entry->as<DynamicEntryLibrary>()->name(std::move(*library_name));
          break;
        }

      case DYNAMIC_TAGS::DT_SONAME :
        {
          dynamic_entry = std::make_unique<DynamicSharedObject>(entry);
          auto sharename = stream_->peek_string_at(dynamic_string_offset + dynamic_entry->value());
          if (!sharename) {
            LIEF_ERR("Can't read library name for DT_SONAME entry");
            break;
          }
          dynamic_entry->as<DynamicSharedObject>()->name(std::move(*sharename));
          break;
        }

      case DYNAMIC_TAGS::DT_RPATH:
        {
          dynamic_entry = std::make_unique<DynamicEntryRpath>(entry);
          auto name = stream_->peek_string_at(dynamic_string_offset + dynamic_entry->value());
          if (!name) {
            LIEF_ERR("Can't read rpath string value for DT_RPATH");
            break;
          }
          dynamic_entry->as<DynamicEntryRpath>()->name(std::move(*name));
          break;
        }

      case DYNAMIC_TAGS::DT_RUNPATH:
        {
          dynamic_entry = std::make_unique<DynamicEntryRunPath>(entry);
          auto name = stream_->peek_string_at(dynamic_string_offset + dynamic_entry->value());
          if (!name) {
            LIEF_ERR("Can't read runpath string value for DT_RUNPATH");
            break;
          }
          dynamic_entry->as<DynamicEntryRunPath>()->name(std::move(*name));
          break;
        }

      case DYNAMIC_TAGS::DT_FLAGS_1:
      case DYNAMIC_TAGS::DT_FLAGS:
        {
          dynamic_entry = std::make_unique<DynamicEntryFlags>(entry);
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
          dynamic_entry = std::make_unique<DynamicEntry>(entry);
          break;
        }

      case DYNAMIC_TAGS::DT_FINI_ARRAY:
      case DYNAMIC_TAGS::DT_INIT_ARRAY:
      case DYNAMIC_TAGS::DT_PREINIT_ARRAY:
        {
          dynamic_entry = std::make_unique<DynamicEntryArray>(entry);
          break;
        }

      case DYNAMIC_TAGS::DT_NULL:
        {
          dynamic_entry = std::make_unique<DynamicEntry>(entry);
          end_of_dynamic = true;
          break;
        }

      default:
        {
          dynamic_entry = std::make_unique<DynamicEntry>(entry);
        }
    }

    if (dynamic_entry != nullptr) {
      binary_->dynamic_entries_.push_back(std::move(dynamic_entry));
    } else {
      LIEF_WARN("dynamic_entry is nullptr !");
    }

    if (end_of_dynamic) {
      break;
    }
  }

  // Check for INIT array
  // ====================
  if (DynamicEntry* dt_init_array = binary_->get(DYNAMIC_TAGS::DT_INIT_ARRAY)) {
    if (DynamicEntry* dt_init_arraysz = binary_->get(DYNAMIC_TAGS::DT_INIT_ARRAYSZ)) {
      binary_->sizing_info_->init_array = dt_init_arraysz->value();
      std::vector<uint64_t>& array = dt_init_array->as<DynamicEntryArray>()->array();
      const auto nb_functions = static_cast<uint32_t>(dt_init_arraysz->value() / sizeof(uint__));
      if (auto offset = binary_->virtual_address_to_offset(dt_init_array->value())) {
        stream_->setpos(*offset);
        for (size_t i = 0; i < nb_functions; ++i) {
          if (auto val = stream_->read_conv<Elf_Addr>()) {
            array.push_back(*val);
          } else {
            break;
          }
        }
      }
    } else {
      LIEF_WARN("The binary is not consistent. Found DT_INIT_ARRAY but missing DT_INIT_ARRAYSZ");
    }
  }


  // Check for FINI array
  // ====================
  if (DynamicEntry* dt_fini_array = binary_->get(DYNAMIC_TAGS::DT_FINI_ARRAY)) {
    if (DynamicEntry* dt_fini_arraysz = binary_->get(DYNAMIC_TAGS::DT_FINI_ARRAYSZ)) {
      binary_->sizing_info_->fini_array = dt_fini_arraysz->value();
      std::vector<uint64_t>& array = dt_fini_array->as<DynamicEntryArray>()->array();

      const auto nb_functions = static_cast<uint32_t>(dt_fini_arraysz->value() / sizeof(uint__));

      if (auto offset = binary_->virtual_address_to_offset(dt_fini_array->value())) {
        stream_->setpos(*offset);
        for (size_t i = 0; i < nb_functions; ++i) {
          if (auto val = stream_->read_conv<Elf_Addr>()) {
            array.push_back(*val);
          } else {
            break;
          }
        }
      }
    } else {
      LIEF_WARN("The binary is not consistent. Found DT_FINI_ARRAY but missing DT_FINI_ARRAYSZ");
    }
  }

  // Check for PREINIT array
  // =======================
  if (DynamicEntry* dt_preini_array = binary_->get(DYNAMIC_TAGS::DT_PREINIT_ARRAY)) {
    if (DynamicEntry* dt_preinit_arraysz = binary_->get(DYNAMIC_TAGS::DT_PREINIT_ARRAYSZ)) {
      binary_->sizing_info_->preinit_array = dt_preinit_arraysz->value();
      std::vector<uint64_t>& array = dt_preini_array->as<DynamicEntryArray>()->array();

      const auto nb_functions = static_cast<uint32_t>(dt_preinit_arraysz->value() / sizeof(uint__));

      if (auto offset = binary_->virtual_address_to_offset(dt_preini_array->value())) {
        stream_->setpos(static_cast<Elf_Off>(*offset));
        for (size_t i = 0; i < nb_functions; ++i) {
          if (auto val = stream_->read_conv<Elf_Addr>()) {
            array.push_back(*val);
          } else {
            break;
          }
        }
      }
    } else {
      LIEF_WARN("The binary is not consistent. Found DT_PREINIT_ARRAY but missing DT_PREINIT_ARRAYSZ");
    }
  }
  return ok();
}


template<typename ELF_T, typename REL_T>
ok_error_t Parser::parse_pltgot_relocations(uint64_t offset, uint64_t size) {
  static_assert(std::is_same<REL_T, typename ELF_T::Elf_Rel>::value ||
                std::is_same<REL_T, typename ELF_T::Elf_Rela>::value, "REL_T must be Elf_Rel or Elf_Rela");
  using Elf_Off  = typename ELF_T::Elf_Off;

  // Already Parsed
  if (binary_->pltgot_relocations().size() > 0) {
    return ok();
  }

  const Elf_Off offset_relocations = offset;
  const uint8_t shift = std::is_same<ELF_T, details::ELF32>::value ? 8 : 32;

  auto nb_entries = static_cast<uint32_t>(size / sizeof(REL_T));

  nb_entries = std::min<uint32_t>(nb_entries, Parser::NB_MAX_RELOCATIONS);

  const ARCH arch = binary_->header_.machine_type();
  stream_->setpos(offset_relocations);
  for (uint32_t i = 0; i < nb_entries; ++i) {
    const auto rel_hdr = stream_->read_conv<REL_T>();
    if (!rel_hdr) {
      break;
    }
    auto reloc = std::make_unique<Relocation>(*rel_hdr);
    reloc->architecture_ = arch;
    reloc->purpose(RELOCATION_PURPOSES::RELOC_PURPOSE_PLTGOT);

    const auto idx = static_cast<uint32_t>(rel_hdr->r_info >> shift);
    if (idx > 0 && idx < binary_->dynamic_symbols_.size()) {
      reloc->symbol_ = binary_->dynamic_symbols_[idx].get();
    }

    binary_->relocations_.push_back(std::move(reloc));
  }
  return ok();
}

struct RelocationSetEq {
  bool operator()(const Relocation* lhs, const Relocation* rhs) const {
    bool check = lhs->address() == rhs->address() &&
                 lhs->type()    == rhs->type()    &&
                 lhs->addend()  == rhs->addend()  &&
                 lhs->info()    == rhs->info()    &&
                 lhs->has_symbol() == rhs->has_symbol();

    if (!check) {
      return false;
    }

    if (lhs->has_symbol()) { // The fact that rhs->has_symbol is checked previously
      return lhs->symbol()->name() == rhs->symbol()->name();
    }
    return check;
  }
};

struct RelocationSetHash {
  size_t operator()(const Relocation* reloc) const {
    Hash hasher;
    hasher.process(reloc->address())
          .process(reloc->type())
          .process(reloc->info())
          .process(reloc->addend());

    const Symbol* sym = reloc->symbol();
    if (sym != nullptr) {
      hasher.process(sym->name());
    }
    return hasher.value();
  }
};

template<typename ELF_T, typename REL_T>
ok_error_t Parser::parse_section_relocations(const Section& section) {
  using Elf_Rel = typename ELF_T::Elf_Rel;
  using Elf_Rela = typename ELF_T::Elf_Rela;

  static_assert(std::is_same<REL_T, Elf_Rel>::value ||
                std::is_same<REL_T, Elf_Rela>::value, "REL_T must be Elf_Rel || Elf_Rela");

  // A relocation section can reference two other sections: a symbol table,
  // identified by the sh_info section header entry, and a section to modify,
  // identified by the sh_link
  // BUT: in practice sh_info and sh_link are inverted
  Section* applies_to = nullptr;
  const size_t sh_info = section.information();
  if (sh_info > 0 && sh_info < binary_->sections_.size()) {
    applies_to = binary_->sections_[sh_info].get();
  }

  // FIXME: Use it
  // Section* section_associated = nullptr;
  // if (section.link() > 0 and section.link() < binary_->sections_.size()) {
  //   const size_t sh_link = section.link();
  //   section_associated = binary_->sections_[sh_link];
  // }

  const uint64_t offset_relocations = section.file_offset();
  const uint8_t shift = std::is_same<ELF_T, details::ELF32>::value ? 8 : 32;

  auto nb_entries = static_cast<uint32_t>(section.size() / sizeof(REL_T));
  nb_entries = std::min<uint32_t>(nb_entries, Parser::NB_MAX_RELOCATIONS);

  std::unordered_set<Relocation*, RelocationSetHash, RelocationSetEq> reloc_hash;
  stream_->setpos(offset_relocations);
  for (uint32_t i = 0; i < nb_entries; ++i) {
    const auto rel_hdr = stream_->read_conv<REL_T>();
    if (!rel_hdr) {
      break;
    }

    auto reloc = std::make_unique<Relocation>(*rel_hdr);
    reloc->architecture_ = binary_->header_.machine_type();
    reloc->section_      = applies_to;
    if (binary_->header().file_type() == ELF::E_TYPE::ET_REL &&
        binary_->segments().size() == 0) {
      reloc->purpose(RELOCATION_PURPOSES::RELOC_PURPOSE_OBJECT);
    }

    const auto idx  = static_cast<uint32_t>(rel_hdr->r_info >> shift);
    if (idx > 0 && idx < binary_->dynamic_symbols_.size()) {
      reloc->symbol_ = binary_->dynamic_symbols_[idx].get();
    } else if (idx < binary_->static_symbols_.size()) {
      reloc->symbol_ = binary_->static_symbols_[idx].get();
    }
    if (reloc_hash.insert(reloc.get()).second) {
      binary_->relocations_.push_back(std::move(reloc));
    }
  }
  return ok();
}


template<typename ELF_T>
ok_error_t Parser::parse_symbol_version_requirement(uint64_t offset, uint32_t nb_entries) {
  using Elf_Verneed = typename ELF_T::Elf_Verneed;
  using Elf_Vernaux = typename ELF_T::Elf_Vernaux;

  LIEF_DEBUG("== Parser Symbol version requirement ==");

  const uint64_t svr_offset = offset;

  LIEF_DEBUG("svr offset: 0x{:x}", svr_offset);

  const uint64_t string_offset = get_dynamic_string_table();

  uint32_t next_symbol_offset = 0;

  for (size_t sym_idx = 0; sym_idx < nb_entries; ++sym_idx) {
    const auto header = stream_->peek_conv<Elf_Verneed>(svr_offset + next_symbol_offset);
    if (!header) {
      break;
    }

    auto symbol_version_requirement = std::make_unique<SymbolVersionRequirement>(*header);
    if (string_offset != 0) {
      auto name = stream_->peek_string_at(string_offset + header->vn_file);
      if (name) {
        symbol_version_requirement->name(std::move(*name));
      }
    }

    const uint32_t nb_symbol_aux = header->vn_cnt;

    if (nb_symbol_aux > 0 && header->vn_aux > 0) {
      uint32_t next_aux_offset = 0;
      for (size_t j = 0; j < nb_symbol_aux; ++j) {
        const uint64_t aux_hdr_off = svr_offset + next_symbol_offset +
                                     header->vn_aux + next_aux_offset;

        const auto aux_header = stream_->peek_conv<Elf_Vernaux>(aux_hdr_off);
        if (!aux_header) {
          break;
        }

        auto svar = std::make_unique<SymbolVersionAuxRequirement>(*aux_header);
        if (string_offset != 0) {
          auto name = stream_->peek_string_at(string_offset + aux_header->vna_name);
          if (name) {
            svar->name(std::move(*name));
          }
        }

        symbol_version_requirement->aux_requirements_.push_back(std::move(svar));
        if (aux_header->vna_next == 0) {
          break;
        }
        next_aux_offset += aux_header->vna_next;
      }

      binary_->symbol_version_requirements_.push_back(std::move(symbol_version_requirement));
    }

    if (header->vn_next == 0) {
      break;
    }
    next_symbol_offset += header->vn_next;
  }


  // Associate Symbol Version with auxiliary symbol
  // Symbol version requirement is used to map
  // SymbolVersion::SymbolVersionAux <------> SymbolVersionAuxRequirement
  //
  // We mask the 15th (7FFF) bit because it sets if this symbol is a hidden on or not
  // but we don't care
  for (const std::unique_ptr<SymbolVersionRequirement>& svr : binary_->symbol_version_requirements_) {
    binary_->sizing_info_->verneed += sizeof(Elf_Verneed);
    for (std::unique_ptr<SymbolVersionAuxRequirement>& svar : svr->aux_requirements_) {
        binary_->sizing_info_->verneed += sizeof(Elf_Vernaux);
        for (const std::unique_ptr<SymbolVersion>& sv : binary_->symbol_version_table_) {
          if ((sv->value() & 0x7FFF) == svar->other()) {
            sv->symbol_aux_ = svar.get();
          }
        }
    }
  }
  return ok();
}


template<typename ELF_T>
ok_error_t Parser::parse_symbol_version_definition(uint64_t offset, uint32_t nb_entries) {
  using Elf_Verdef  = typename ELF_T::Elf_Verdef;
  using Elf_Verdaux = typename ELF_T::Elf_Verdaux;

  const uint64_t string_offset = get_dynamic_string_table();
  uint32_t next_symbol_offset = 0;

  for (size_t i = 0; i < nb_entries; ++i) {
    const uint64_t struct_offset = offset + next_symbol_offset;
    const auto svd_header = stream_->peek_conv<Elf_Verdef>(struct_offset);
    if (!svd_header) {
      break;
    }

    auto symbol_version_definition = std::make_unique<SymbolVersionDefinition>(*svd_header);
    uint32_t nb_aux_symbols = svd_header->vd_cnt;
    uint32_t next_aux_offset = 0;
    for (size_t j = 0; j < nb_aux_symbols; ++j) {
      const uint64_t struct_offset = offset + next_symbol_offset + svd_header->vd_aux + next_aux_offset;
      const auto svda_header = stream_->peek_conv<Elf_Verdaux>(struct_offset);
      if (!svda_header) {
        break;
      }

      if (string_offset != 0) {
        auto name  = stream_->peek_string_at(string_offset + svda_header->vda_name);
        if (name) {
          symbol_version_definition->symbol_version_aux_.emplace_back(new SymbolVersionAux{std::move(*name)});
        }
      }

      // Additional check
      if (svda_header->vda_next == 0) {
        break;
      }

      next_aux_offset += svda_header->vda_next;
    }

    binary_->symbol_version_definition_.push_back(std::move(symbol_version_definition));

    // Additional check
    if (svd_header->vd_next == 0) {
      break;
    }

    next_symbol_offset += svd_header->vd_next;
  }

  // Associate Symbol Version with auxiliary symbol
  // We mask the 15th bit because it sets if this symbol is a hidden on or not
  // but we don't care
  for (std::unique_ptr<SymbolVersionDefinition>& svd : binary_->symbol_version_definition_) {
    binary_->sizing_info_->verdef += sizeof(Elf_Verdef);
    for (std::unique_ptr<SymbolVersionAux>& sva : svd->symbol_version_aux_) {
      binary_->sizing_info_->verdef += sizeof(Elf_Verdaux);
      for (std::unique_ptr<SymbolVersion>& sv : binary_->symbol_version_table_) {
        if (svd->ndx() > 1 && (sv->value() & 0x7FFF) == svd->ndx() && !sv->symbol_aux_) {
          sv->symbol_aux_ = sva.get();
        }
      }
    }
  }
  return ok();
}

// See: https://github.com/lattera/glibc/blob/master/elf/dl-lookup.c#L860
// and  https://github.com/lattera/glibc/blob/master/elf/dl-lookup.c#L226
template<typename ELF_T>
ok_error_t Parser::parse_symbol_gnu_hash(uint64_t offset) {
  using uint__  = typename ELF_T::uint;

  static constexpr uint32_t NB_MAX_WORDS   = 90000;
  static constexpr uint32_t NB_MAX_BUCKETS = 90000;
  static constexpr uint32_t MAX_NB_HASH    = 1000000;

  LIEF_DEBUG("== Parser symbol GNU hash ==");
  auto gnuhash = std::make_unique<GnuHash>();
  gnuhash->c_ = sizeof(uint__) * 8;

  stream_->setpos(offset);

  uint32_t nbuckets  = 0;
  uint32_t maskwords = 0;

  if (auto res = stream_->read_conv<uint32_t>()) {
    nbuckets = std::min(*res, NB_MAX_BUCKETS);
  } else {
    LIEF_ERR("Can't read the number of buckets");
    return make_error_code(lief_errors::read_error);
  }

  if (auto res = stream_->read_conv<uint32_t>()) {
    gnuhash->symbol_index_ = *res;
  } else {
    LIEF_ERR("Can't read the symndx");
    return make_error_code(lief_errors::read_error);
  }

  if (auto res = stream_->read_conv<uint32_t>()) {
    maskwords = std::min(*res, NB_MAX_MASKWORD);
  } else {
    LIEF_ERR("Can't read the maskwords");
    return make_error_code(lief_errors::read_error);
  }

  if (auto res = stream_->read_conv<uint32_t>()) {
    gnuhash->shift2_ = *res;
  } else {
    LIEF_ERR("Can't read the shift2");
    return make_error_code(lief_errors::read_error);
  }

  if (maskwords & (maskwords - 1)) {
    LIEF_WARN("maskwords is not a power of 2");
  }

  if (maskwords < NB_MAX_WORDS) {
    gnuhash->bloom_filters_.reserve(maskwords);

    for (size_t i = 0; i < maskwords; ++i) {
      if (auto maskword = stream_->read_conv<uint__>()) {
        gnuhash->bloom_filters_.push_back(*maskword);
      } else {
        LIEF_ERR("Can't read maskwords #{:d}", i);
        break;
      }
    }
  } else {
    LIEF_ERR("GNU Hash, maskwords corrupted");
  }

  if (nbuckets > NB_MAX_BUCKETS) {
    LIEF_ERR("Number of bucket corrupted! (Too big)");
    return make_error_code(lief_errors::corrupted);
  }

  gnuhash->buckets_.reserve(nbuckets);

  for (size_t i = 0; i < nbuckets; ++i) {
    if (auto res = stream_->read_conv<uint32_t>()) {
      gnuhash->buckets_.push_back(*res);
    } else {
      LIEF_ERR("Can't read bucket #{}", i);
      break;
    }
  }

  const auto dynsymcount = static_cast<uint32_t>(binary_->dynamic_symbols_.size());
  if (dynsymcount >= gnuhash->symbol_index_) {
    const uint32_t nb_hash = dynsymcount - gnuhash->symbol_index_;

    if (nb_hash < MAX_NB_HASH) {
      gnuhash->hash_values_.reserve(nb_hash);
      for (size_t i = 0; i < nb_hash; ++i) {
        if (auto res = stream_->read_conv<uint32_t>()) {
          gnuhash->hash_values_.push_back(*res);
        } else {
          LIEF_ERR("Can't read hash #{}", i);
          break;
        }
      }
    } else {
      LIEF_ERR("The number of hash entries seems too high ({:d})", nb_hash);
    }
  } else {
    LIEF_ERR("GNU Hash, symndx corrupted");
  }
  binary_->gnu_hash_ = std::move(gnuhash);
  binary_->sizing_info_->gnu_hash = stream_->pos() - offset;
  return ok();
}

}
}
