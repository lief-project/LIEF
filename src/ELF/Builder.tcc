/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
 * Copyright 2017 - 2021, NVIDIA CORPORATION. All rights reserved.
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
#include <cassert>
#include <numeric>
#include <unordered_map>

#include "logging.hpp"

#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/ELF/utils.hpp"
#include "LIEF/ELF/EnumToString.hpp"
#include "LIEF/ELF/Builder.hpp"
#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/Section.hpp"
#include "LIEF/ELF/Segment.hpp"
#include "LIEF/ELF/Symbol.hpp"
#include "LIEF/ELF/DynamicEntry.hpp"
#include "LIEF/ELF/DynamicEntryArray.hpp"
#include "LIEF/ELF/DynamicEntryLibrary.hpp"
#include "LIEF/ELF/DynamicSharedObject.hpp"
#include "LIEF/ELF/DynamicEntryRunPath.hpp"
#include "LIEF/ELF/DynamicEntryRpath.hpp"
#include "LIEF/ELF/Relocation.hpp"
#include "LIEF/ELF/SymbolVersion.hpp"
#include "LIEF/ELF/SymbolVersionDefinition.hpp"
#include "LIEF/ELF/SymbolVersionAux.hpp"
#include "LIEF/ELF/SymbolVersionRequirement.hpp"
#include "LIEF/ELF/SymbolVersionAuxRequirement.hpp"
#include "LIEF/ELF/Note.hpp"

#include "LIEF/ELF/Builder.hpp"
#include "LIEF/errors.hpp"

#include "ELF/Structures.hpp"
#include "ELF/SizingInfo.hpp"
#include "Object.tcc"
#include "ExeLayout.hpp"
#include "ObjectFileLayout.hpp"



namespace LIEF {
namespace ELF {

template<class ELF_T>
ok_error_t Builder::build() {
  const char* type = ((binary_->type_ == ELF_CLASS::ELFCLASS32) ? "ELF32" : "ELF64");
  LIEF_DEBUG("== Re-building {} ==", type);

  const E_TYPE file_type = binary_->header().file_type();
  switch (file_type) {
    case E_TYPE::ET_DYN:
    case E_TYPE::ET_EXEC:
    case E_TYPE::ET_CORE:
      {
        auto res = build_exe_lib<ELF_T>();
        if (!res) {
          LIEF_ERR("The builder failed for the given executable/library. "
                   "Check the error output");
          return make_error_code(lief_errors::build_error);
        }
        return ok();
      }

    case E_TYPE::ET_REL:
      {
        auto res = build_relocatable<ELF_T>();
        if (!res) {
          LIEF_ERR("The builder failed for the given object file. "
                   "Check the error output");
          return make_error_code(lief_errors::build_error);
        }
        return ok();
      }

    default:
      {
        LIEF_ERR("ELF file '{}' are not supported by LIEF", to_string(file_type));
        return make_error_code(lief_errors::not_supported);
      }
  }
}


template<typename ELF_T>
ok_error_t Builder::build_exe_lib() {
  auto* layout = static_cast<ExeLayout*>(layout_.get());
  // Sort dynamic symbols
  uint32_t new_symndx = sort_dynamic_symbols();
  layout->set_dyn_sym_idx(new_symndx);

  Segment* pt_interp = binary_->get(SEGMENT_TYPES::PT_INTERP);
  if (config_.interpreter) {
    if (pt_interp != nullptr) {
      const size_t interpt_size = layout->interpreter_size<ELF_T>();
      const uint64_t osize = binary_->sizing_info_->interpreter;
      if (interpt_size > osize || config_.force_relocate) {
        LIEF_DEBUG("[-] Need to relocate .interp section (0x{:x} new bytes)", interpt_size - osize);
        layout->relocate_interpreter(interpt_size);
      } else { LIEF_DEBUG(".interp: -0x{:x} bytes", osize - interpt_size); }
    } else if (!binary_->interpreter_.empty()) { // Directly access private field as we want to avoid
                                                 // has_interpreter() check

      // In this case, the original ELF file didn't have an interpreter
      // and the user added one.
      const size_t interpt_size = layout->interpreter_size<ELF_T>();
      LIEF_DEBUG("[-] Need to create an .interp section / segment");
      layout->relocate_interpreter(interpt_size);
    }
  }

  if (binary_->has(SEGMENT_TYPES::PT_NOTE) && config_.notes) {
    const size_t notes_size = layout->note_size<ELF_T>();
    std::vector<Segment*> note_segments;
    for (std::unique_ptr<Segment>& seg : binary_->segments_) {
      if (seg->type() == SEGMENT_TYPES::PT_NOTE) {
        note_segments.push_back(seg.get());
      }
    }
    // TODO(romain): should we try to find the largest one?
    const size_t nb_segment_notes = note_segments.size();
    if (nb_segment_notes > 1) {
      while (note_segments.size() > 1) {
        binary_->remove(*note_segments.back());
        note_segments.pop_back();
      }
    }

    Segment& note_segment = *note_segments.back();

    if (notes_size > note_segment.physical_size() || nb_segment_notes > 1 || config_.force_relocate) {
      LIEF_DEBUG("[-] Need to relocate .note.* segments (0x{:x} new bytes)",
          notes_size - note_segment.physical_size());
      layout->relocate_notes(true);
    } else { /*LIEF_DEBUG(".notes: -0x{:x} bytes", note_segment.physical_size() - notes_size);*/ }
  }

  if (binary_->has(DYNAMIC_TAGS::DT_GNU_HASH) && config_.gnu_hash) {
    const size_t needed_size = layout->symbol_gnu_hash_size<ELF_T>();
    const uint64_t osize = binary_->sizing_info_->gnu_hash;
    const bool should_relocate = needed_size > osize || config_.force_relocate;
    if (should_relocate) {
      LIEF_DEBUG("[-] Need to relocate DT_GNU_HASH (0x{:x} new bytes)", needed_size - osize);
      layout->relocate_gnu_hash(true);
    } else { LIEF_DEBUG("DT_GNU_HASH: -0x{:x} bytes", osize - needed_size); }
  }

  if (binary_->has(DYNAMIC_TAGS::DT_HASH) && config_.dt_hash) {
    const size_t needed_size = layout->symbol_sysv_hash_size<ELF_T>();
    const uint64_t osize = binary_->sizing_info_->hash;
    const bool should_relocate = needed_size > osize || config_.force_relocate;
    if (should_relocate) {
      LIEF_DEBUG("[-] Need to relocate DT_HASH (0x{:x} new bytes)", needed_size - osize);
      layout->relocate_sysv_hash(needed_size);
    } else { LIEF_DEBUG("DT_HASH: -0x{:x} bytes", osize - needed_size); }
  }

  if (binary_->has(SEGMENT_TYPES::PT_DYNAMIC) && config_.dynamic_section) {
    const size_t dynamic_needed_size = layout->dynamic_size<ELF_T>();
    const uint64_t osize = binary_->sizing_info_->dynamic;
    const bool should_relocate = dynamic_needed_size > osize || config_.force_relocate;
    if (should_relocate) {
      LIEF_DEBUG("[-] Need to relocate .dynamic section (0x{:x} new bytes)", dynamic_needed_size - osize);
      layout->relocate_dynamic(dynamic_needed_size);
    } else { LIEF_DEBUG("PT_DYNAMIC: -0x{:x} bytes", osize - dynamic_needed_size); }
  }

  if (binary_->has(DYNAMIC_TAGS::DT_RELA) || binary_->has(DYNAMIC_TAGS::DT_REL)) {
    const size_t dyn_reloc_needed_size = layout->dynamic_relocations_size<ELF_T>();
    if (config_.rela) {
      const uint64_t osize = binary_->sizing_info_->rela;
      const bool should_relocate = dyn_reloc_needed_size > osize || config_.force_relocate;
      if (should_relocate) {
        LIEF_DEBUG("[-] Need to relocate DT_REL(A) (0x{:x} new bytes)", dyn_reloc_needed_size - osize);
        layout->relocate_dyn_reloc(dyn_reloc_needed_size);
      } else { LIEF_DEBUG("DT_REL(A): -0x{:x} bytes", osize - dyn_reloc_needed_size); }
    }
  }

  if (config_.jmprel && binary_->has(DYNAMIC_TAGS::DT_JMPREL)) {
    const size_t plt_reloc_needed_size = layout->pltgot_relocations_size<ELF_T>();
    const uint64_t osize = binary_->sizing_info_->jmprel;
    const bool should_relocate = plt_reloc_needed_size > osize || config_.force_relocate;
    if (should_relocate) {
      LIEF_DEBUG("[-] Need to relocate DT_JMPREL section (0x{:x} new bytes)", plt_reloc_needed_size - osize);
      layout->relocate_plt_reloc(plt_reloc_needed_size);
    } else { LIEF_DEBUG("DT_JMPREL: -0x{:x} bytes", osize - plt_reloc_needed_size); }
  }

  if (config_.dyn_str && binary_->has(DYNAMIC_TAGS::DT_STRTAB)) {
    const size_t needed_size = layout->dynstr_size<ELF_T>();
    const uint64_t osize  = binary_->sizing_info_->dynstr;
    const bool should_relocate = needed_size > osize || config_.force_relocate;
    if (should_relocate) {
      LIEF_DEBUG("[-] Need to relocate DT_STRTAB (0x{:x} new bytes)", needed_size - osize);
      layout->relocate_dynstr(true);
    } else { LIEF_DEBUG("DT_STRTAB: -0x{:x} bytes", osize - needed_size); }
  }

  if (config_.symtab && binary_->has(DYNAMIC_TAGS::DT_SYMTAB)) {
    const size_t dynsym_needed_size = layout->dynsym_size<ELF_T>();
    const uint64_t osize = binary_->sizing_info_->dynsym;
    const bool should_relocate = dynsym_needed_size > osize || config_.force_relocate;
    if (should_relocate) {
      LIEF_DEBUG("[-] Need to relocate DT_SYMTAB (0x{:x} new bytes)", dynsym_needed_size - osize);
      layout->relocate_dynsym(dynsym_needed_size);
    } else { LIEF_DEBUG("DT_SYMTAB: -0x{:x} bytes", osize - dynsym_needed_size); }
  }

  if (binary_->has(DYNAMIC_TAGS::DT_INIT_ARRAY) && binary_->has(DYNAMIC_TAGS::DT_INIT_ARRAYSZ) &&
      config_.init_array)
  {
    const size_t needed_size = layout->dynamic_arraysize<ELF_T>(DYNAMIC_TAGS::DT_INIT_ARRAY);
    const uint64_t osize = binary_->sizing_info_->init_array;
    const bool should_relocate = needed_size > osize;
    if (should_relocate) {
      if (binary_->has_symbol("__libc_start_main")) {
        LIEF_WARN("Relocating DT_INIT_ARRAY on Linux may corrupt the final binary");
      }
      LIEF_DEBUG("[-] Need to relocate DT_INIT_ARRAY (0x{:x} new bytes)", osize - needed_size);
      layout->relocate_init_array(needed_size);
    } else { LIEF_DEBUG("DT_INIT_ARRAY: -0x{:x} bytes", osize - needed_size); }
  }

  if (binary_->has(DYNAMIC_TAGS::DT_PREINIT_ARRAY) && binary_->has(DYNAMIC_TAGS::DT_PREINIT_ARRAYSZ) &&
      config_.preinit_array)
  {
    const size_t needed_size = layout->dynamic_arraysize<ELF_T>(DYNAMIC_TAGS::DT_PREINIT_ARRAY);
    const uint64_t osize = binary_->sizing_info_->preinit_array;
    const bool should_relocate = needed_size > osize;
    if (should_relocate) {
      LIEF_DEBUG("[-] Need to relocate DT_PREINIT_ARRAY (0x{:x} new bytes)", osize - needed_size);
      layout->relocate_preinit_array(needed_size);
    } else { LIEF_DEBUG("DT_PREINIT_ARRAY: -0x{:x} bytes", osize - needed_size); }
  }

  if (binary_->has(DYNAMIC_TAGS::DT_FINI_ARRAY) && binary_->has(DYNAMIC_TAGS::DT_FINI_ARRAYSZ) &&
      config_.fini_array)
  {
    const size_t needed_size   = layout->dynamic_arraysize<ELF_T>(DYNAMIC_TAGS::DT_FINI_ARRAY);
    const uint64_t osize       = binary_->sizing_info_->fini_array;
    const bool should_relocate = needed_size > osize;
    if (should_relocate) {
      if (binary_->has_symbol("__libc_start_main")) {
        LIEF_WARN("Relocating .fini_array on Linux may corrupt the final binary");
      }
      LIEF_DEBUG("[-] Need to relocate DT_FINI_ARRAY (0x{:x} new bytes)", osize - needed_size);
      layout->relocate_fini_array(needed_size);
    } else { LIEF_DEBUG("DT_FINI_ARRAY: -0x{:x} bytes", osize - needed_size); }
  }

  if (binary_->has(DYNAMIC_TAGS::DT_VERSYM) && config_.sym_versym) {
    const size_t symver_needed_size = layout->symbol_version<ELF_T>();
    const uint64_t osize       = binary_->sizing_info_->versym;
    const bool should_relocate = symver_needed_size > osize || config_.force_relocate;
    if (should_relocate) {
      LIEF_DEBUG("[-] Need to relocate DT_VERSYM (0x{:x} new bytes)", symver_needed_size - osize);
      layout->relocate_symver(symver_needed_size);
    } else { LIEF_DEBUG("DT_VERSYM: -0x{:x} bytes", osize - symver_needed_size); }
  }

  if (binary_->has(DYNAMIC_TAGS::DT_VERDEF) && config_.sym_verdef) {
    const size_t symvdef_needed_size = layout->symbol_vdef_size<ELF_T>();
    const uint64_t osize       = binary_->sizing_info_->verdef;
    const bool should_relocate = symvdef_needed_size > osize || config_.force_relocate;
    if (should_relocate) {
      LIEF_DEBUG("[-] Need to relocate DT_VERDEF (0x{:x} new bytes)", symvdef_needed_size - osize);
      layout->relocate_symverd(symvdef_needed_size);
    } else { LIEF_DEBUG("DT_VERDEF: -0x{:x} bytes", osize - symvdef_needed_size); }
  }

  if (binary_->has(DYNAMIC_TAGS::DT_VERNEED) && config_.sym_verneed) {
    const size_t symvreq_needed_size = layout->symbol_vreq_size<ELF_T>();
    const uint64_t osize       = binary_->sizing_info_->verneed;
    const bool should_relocate = symvreq_needed_size > osize || config_.force_relocate;
    if (should_relocate) {
      LIEF_DEBUG("[-] Need to relocate DT_VERNEED (0x{:x} new bytes)", symvreq_needed_size - osize);
      layout->relocate_symverr(symvreq_needed_size);
    } else { LIEF_DEBUG("DT_VERNEED: -0x{:x} bytes", osize - symvreq_needed_size); }
  }

  const Header& header = binary_->header();
  if (header.section_name_table_idx() > 0 && !binary_->sections_.empty() ) {
    if (header.section_name_table_idx() >= binary_->sections_.size()) {
      LIEF_ERR("Section string table out of bound");
    } else {
      std::unique_ptr<Section>& string_names_section = binary_->sections_[header.section_name_table_idx()];
      const size_t shstr_size = layout->section_shstr_size();
      if (shstr_size > string_names_section->size() || config_.force_relocate) {
        LIEF_DEBUG("[-] Need to relocate '{}' section (0x{:x} new bytes)",
                   string_names_section->name(), shstr_size - string_names_section->size());
        layout->relocate_shstr(true);
      }
    }
  }

  // Check if we should relocate or create the .strtab section
  Section* sec_symtab = binary_->get(ELF_SECTION_TYPES::SHT_SYMTAB);
  if (!layout->is_strtab_shared_shstrtab() && !binary_->static_symbols_.empty()) {
    // There is no .symtab section => create .strtab
    if (sec_symtab == nullptr) {
      // Required since it writes the .strtab content in cache
      LIEF_DEBUG("[-] Missing .symtab, need to relocate the .strtab section");
      layout->relocate_strtab(layout->section_strtab_size());
    } else {
      // The .symtab exists
      const auto sections = binary_->sections();
      const size_t strtab_idx = sec_symtab->link();
      if (strtab_idx == 0 || strtab_idx >= sections.size()) {
        LIEF_ERR("The .strtab index seems corrupted");
        layout->relocate_strtab(layout->section_strtab_size());
      } else {
        Section& strtab = sections[strtab_idx];
        const size_t strtab_needed_size = layout->section_strtab_size();
        if (strtab_needed_size > strtab.size() || config_.force_relocate) {
          LIEF_DEBUG("[-] Need to relocate .strtab section (0x{:x} new bytes)",
                     strtab_needed_size - strtab.size());
          layout->relocate_strtab(layout->section_strtab_size());
        }
        LIEF_DEBUG("strtab section: {}", strtab.name());
        layout->set_strtab_section(strtab);
      }
    }
  }

  if (sec_symtab != nullptr) {
    const size_t needed_size = layout->static_sym_size<ELF_T>();
    if (needed_size > sec_symtab->size() || config_.force_relocate) {
      LIEF_DEBUG("[-] Need to relocate '{}' section (0x{:x} new bytes)",
                 sec_symtab->name(), needed_size - sec_symtab->size());
      layout->relocate_symtab(needed_size);
    }
  }
  else if (!binary_->static_symbols_.empty()) {
    // In this case the binary was stripped but the user
    // added symbols => We have to craft a new section that will contain the symtab
    LIEF_DEBUG("Need to create a new .symtab section");
    const size_t needed_size = layout->static_sym_size<ELF_T>();
    layout->relocate_symtab(needed_size);
  }

  auto res = layout->relocate();
  if (!res) {
    LIEF_ERR("Failing to create a new layout for this binary");
    return make_error_code(lief_errors::build_error);
  }

  // ----------------------------------------------------------------
  // At this point all the VAs are consistent with the new layout
  // and we have enough space to write ELF elements
  // ----------------------------------------------------------------

  if (config_.gnu_hash || config_.dt_hash) {
    LIEF_SW_START(sw);
    build_hash_table<ELF_T>();
    LIEF_SW_END("hast table built in {}", duration_cast<std::chrono::milliseconds>(sw.elapsed()));
  }

  if (config_.dyn_str) {
    if (DynamicEntry* dt_strtab = binary_->get(DYNAMIC_TAGS::DT_STRTAB)) {
      binary_->patch_address(dt_strtab->value(), layout->raw_dynstr());
    }
  }

  if (config_.interpreter && binary_->has(SEGMENT_TYPES::PT_INTERP)) {
    LIEF_SW_START(sw);
    build_interpreter<ELF_T>();
    LIEF_SW_END(".interp built in {}", duration_cast<std::chrono::milliseconds>(sw.elapsed()));
  }

  if (config_.notes && binary_->has(SEGMENT_TYPES::PT_NOTE)) {
    LIEF_SW_START(sw);
    build_notes<ELF_T>();
    LIEF_SW_END(".note built in {}", duration_cast<std::chrono::milliseconds>(sw.elapsed()));
  }

  if (config_.dynamic_section && binary_->has(SEGMENT_TYPES::PT_DYNAMIC)) {
    LIEF_SW_START(sw);
    build_dynamic_section<ELF_T>();
    LIEF_SW_END(".dynamic built in {}", duration_cast<std::chrono::milliseconds>(sw.elapsed()));
  }

  if (config_.symtab && binary_->has(DYNAMIC_TAGS::DT_SYMTAB)) {
    LIEF_SW_START(sw);
    build_dynamic_symbols<ELF_T>();
    LIEF_SW_END(".dynsym built in {}", duration_cast<std::chrono::milliseconds>(sw.elapsed()));
  }

  if (config_.sym_versym && binary_->has(DYNAMIC_TAGS::DT_VERSYM)) {
    LIEF_SW_START(sw);
    build_symbol_version<ELF_T>();
    LIEF_SW_END(".gnu.version built in {}", duration_cast<std::chrono::milliseconds>(sw.elapsed()));
  }

  if (config_.sym_verdef && binary_->has(DYNAMIC_TAGS::DT_VERDEF)) {
    LIEF_SW_START(sw);
    build_symbol_definition<ELF_T>();
    LIEF_SW_END(".gnu.version_d built in {}", duration_cast<std::chrono::milliseconds>(sw.elapsed()));
  }

  if (config_.sym_verneed && binary_->has(DYNAMIC_TAGS::DT_VERNEED)) {
    LIEF_SW_START(sw);
    build_symbol_requirement<ELF_T>();
    LIEF_SW_END(".gnu.version_r built in {}", duration_cast<std::chrono::milliseconds>(sw.elapsed()));
  }

  if (config_.rela) {
    LIEF_SW_START(sw);
    build_dynamic_relocations<ELF_T>();
    LIEF_SW_END(".rela.dyn built in {}", duration_cast<std::chrono::milliseconds>(sw.elapsed()));
  }

  if (config_.jmprel) {
    LIEF_SW_START(sw);
    build_pltgot_relocations<ELF_T>();
    LIEF_SW_END(".rela.plt built in {}", duration_cast<std::chrono::milliseconds>(sw.elapsed()));
  }

  if (config_.static_symtab && binary_->has(ELF_SECTION_TYPES::SHT_SYMTAB)) {
    LIEF_SW_START(sw);
    build_static_symbols<ELF_T>();
    LIEF_SW_END(".symtab built in {}", duration_cast<std::chrono::milliseconds>(sw.elapsed()));
  }

  // Build sections
  if (!binary_->sections_.empty()) {
    build_sections<ELF_T>();
  }

  // Build PHDR
  if (binary_->header().program_headers_offset() > 0) {
    build_segments<ELF_T>();
  } else {
    LIEF_WARN("Segments offset is null");
  }

  build<ELF_T>(binary_->header());
  build_overlay<ELF_T>();
  return ok();
}


template<class ELF_T>
ok_error_t Builder::process_object_relocations() {

  auto* layout = static_cast<ObjectFileLayout*>(layout_.get());

  const auto it_relocations = binary_->object_relocations();

  if (it_relocations.empty()) {
    LIEF_DEBUG("No relocations. Nothing to do");
    return ok();
  }

  using Elf_Rela = typename ELF_T::Elf_Rela;
  using Elf_Rel  = typename ELF_T::Elf_Rel;

  bool is_rela = it_relocations[0].is_rela();
  const size_t sizeof_rel = is_rela ? sizeof(Elf_Rela) : sizeof(Elf_Rel);

  const auto sections = binary_->sections();
  ObjectFileLayout::sections_reloc_map_t& sections_reloc_map = layout->sections_reloc_map();
  ObjectFileLayout::relocations_map_t& relocations_map = layout->relocation_map();
  ObjectFileLayout::rel_sections_size_t& rel_sections_size = layout->rel_sections_size();

  for (Section& sec : sections) {
    const ELF_SECTION_TYPES type = sec.type();
    if (type != ELF_SECTION_TYPES::SHT_RELA && type != ELF_SECTION_TYPES::SHT_REL) {
      continue;
    }
    const size_t sh_info = sec.information();
    if (sh_info == 0 || sh_info >= sections.size()) {
      LIEF_WARN("Relocation index for section '{}' is corrupted");
      continue;
    }
    Section& associated = sections[sh_info];
    sections_reloc_map[&associated] = &sec; // e.g (.text, .text.rela)
  }

  for (Relocation& reloc : it_relocations) {
    Section* sec = reloc.section();
    if (sec == nullptr) {
      LIEF_WARN("Relocation @0x{:x} misses a section", reloc.address());
      continue;
    }
    LIEF_DEBUG("Section for reloc 0x{:x} -> {}", reloc.address(), sec->name());
    relocations_map[sec].push_back(&reloc);
    auto it_reloc_sec = sections_reloc_map.find(sec);
    if (it_reloc_sec == std::end(sections_reloc_map)) {
      LIEF_WARN("Can find the relocation section associated with '{}'", sec->name());
      continue;
    }
    Section* reloc_section = it_reloc_sec->second;
    rel_sections_size[reloc_section] += sizeof_rel;
  }

  for (const auto& p : rel_sections_size) {
    const Section* section = p.first;
    const size_t need_size = p.second;
    if (need_size > section->size()) {
      LIEF_DEBUG("Need to relocate '{}'", section->name());
      layout->relocate_section(*section, need_size);
    }
  }
  return ok();
}

template<class ELF_T>
ok_error_t Builder::build_relocatable() {
  auto* layout = static_cast<ObjectFileLayout*>(layout_.get());

  Header& header = binary_->header();
  uint32_t new_symndx = sort_dynamic_symbols();
  layout->set_dyn_sym_idx(new_symndx);

  // Check if we should relocate the .shstrtab
  if (header.section_name_table_idx() > 0) {
    if (header.section_name_table_idx() >= binary_->sections_.size()) {
      LIEF_ERR("Section string table out of bound");
      return make_error_code(lief_errors::file_format_error);
    }
    std::unique_ptr<Section>& string_names_section = binary_->sections_[header.section_name_table_idx()];
    const size_t shstr_size = layout->section_shstr_size();
    if (shstr_size > string_names_section->size() || config_.force_relocate) {
      LIEF_DEBUG("[-] Need to relocate '{}' section (0x{:x} new bytes)",
                 string_names_section->name(), shstr_size - string_names_section->size());
      layout->relocate_section(*string_names_section, shstr_size);
    }
  }

  // Check the .symtab section
  Section* symtab = binary_->get(ELF_SECTION_TYPES::SHT_SYMTAB);
  if (symtab != nullptr) {
    const size_t needed_size = layout->symtab_size<ELF_T>();
    if (needed_size > symtab->size() || config_.force_relocate) {
      LIEF_DEBUG("[-] Need to relocate '{}' section (0x{:x} new bytes)",
                 symtab->name(), symtab->size() - needed_size);
      layout->relocate_section(*symtab, needed_size);
    }
  }

  // Check if we should relocate or create a .strtab section.
  // We assume that a .shstrtab is always prensent
  if (!layout->is_strtab_shared_shstrtab() && !binary_->static_symbols_.empty()) {
    Section* sec_symtab = binary_->get(ELF_SECTION_TYPES::SHT_SYMTAB);
    if (sec_symtab == nullptr) {
      LIEF_ERR("Object file without a symtab section is not supported. Please consider submitting an issue.");
      return make_error_code(lief_errors::not_supported);
    }
    // The .symtab exists
    const auto sections = binary_->sections();
    const size_t strtab_idx = sec_symtab->link();
    if (strtab_idx == 0 || strtab_idx >= sections.size()) {
      LIEF_ERR("The .strtab index is corrupted");
    } else {
      Section& strtab = sections[strtab_idx];
      const size_t strtab_needed_size = layout->section_strtab_size();
      if (strtab_needed_size > strtab.size() || config_.force_relocate) {
        LIEF_DEBUG("[-] Need to relocate .strtab section (0x{:x} new bytes)",
                   strtab_needed_size - strtab.size());
        layout->relocate_section(strtab, strtab_needed_size);
      }
      layout->set_strtab_section(strtab);
    }
  }
  process_object_relocations<ELF_T>();

  auto res = layout->relocate();
  if (!res) {
    LIEF_ERR("Error(s) occurred during the layout relocation.");
    return make_error_code(lief_errors::build_error);
  }

  if (binary_->has(ELF_SECTION_TYPES::SHT_SYMTAB)) {
    build_obj_symbols<ELF_T>();
  }

  build_section_relocations<ELF_T>();

  // Since object file only have sections, we don't have to process segments
  if (!binary_->sections_.empty()) {
    build_sections<ELF_T>();
  }

  build<ELF_T>(binary_->header());
  build_overlay<ELF_T>();
  return ok();
}


template<typename ELF_T>
ok_error_t Builder::build(const Header& header) {;
  using Elf_Half = typename ELF_T::Elf_Half;
  using Elf_Word = typename ELF_T::Elf_Word;
  using Elf_Addr = typename ELF_T::Elf_Addr;
  using Elf_Off  = typename ELF_T::Elf_Off;
  using Elf_Word = typename ELF_T::Elf_Word;

  using Elf_Ehdr = typename ELF_T::Elf_Ehdr;

  Elf_Ehdr ehdr;

  ehdr.e_type      = static_cast<Elf_Half>(header.file_type());
  ehdr.e_machine   = static_cast<Elf_Half>(header.machine_type());
  ehdr.e_version   = static_cast<Elf_Word>(header.object_file_version());
  ehdr.e_entry     = static_cast<Elf_Addr>(header.entrypoint());
  ehdr.e_phoff     = static_cast<Elf_Off>(header.program_headers_offset());
  ehdr.e_shoff     = static_cast<Elf_Off>(header.section_headers_offset());
  ehdr.e_flags     = static_cast<Elf_Word>(header.processor_flag());
  ehdr.e_ehsize    = static_cast<Elf_Half>(header.header_size());
  ehdr.e_phentsize = static_cast<Elf_Half>(header.program_header_size());
  ehdr.e_phnum     = static_cast<Elf_Half>(header.numberof_segments());
  ehdr.e_shentsize = static_cast<Elf_Half>(header.section_header_size());
  ehdr.e_shnum     = static_cast<Elf_Half>(header.numberof_sections());
  ehdr.e_shstrndx  = static_cast<Elf_Half>(header.section_name_table_idx());

  std::copy(std::begin(header.identity()), std::end(header.identity()),
            std::begin(ehdr.e_ident));

  ios_.seekp(0);
  ios_.write_conv<Elf_Ehdr>(ehdr);
  return ok();
}


template<typename ELF_T>
ok_error_t Builder::build_sections() {
  using Elf_Word = typename ELF_T::Elf_Word;
  using Elf_Addr = typename ELF_T::Elf_Addr;
  using Elf_Off  = typename ELF_T::Elf_Off;
  using Elf_Word = typename ELF_T::Elf_Word;

  using Elf_Shdr = typename ELF_T::Elf_Shdr;

  if (binary_->sections_.empty()) {
    return ok();
  }


  LIEF_DEBUG("[+] Build sections");

  const Header& header = binary_->header();
  const Elf_Off section_headers_offset = header.section_headers_offset();
  if (section_headers_offset == 0) {
    return ok();
  }

  if (header.section_name_table_idx() < binary_->sections_.size()) {
    std::unique_ptr<Section>& string_names_section = binary_->sections_[header.section_name_table_idx()];
    string_names_section->content(layout_->raw_shstr());
  }

  const std::unordered_map<std::string, size_t>& shstr_map = layout_->shstr_map();
  for (size_t i = 0; i < binary_->sections_.size(); ++i) {
    const std::unique_ptr<Section>& section = binary_->sections_[i];
    LIEF_DEBUG("[FRAME  ] {}", section->is_frame());
    if (!section->is_frame()       &&
        section->size()        > 0 &&
        section->file_offset() > 0 &&
        // SHT_NOTBITS sections should not be considered.
        // Nevertheless, some (malformed or tricky) ELF binaries
        // might use this type to put content.
        section->type() != ELF_SECTION_TYPES::SHT_NOBITS) {
      span<const uint8_t> content = section->content();
      LIEF_DEBUG("[Content] {:20}: 0x{:010x} - 0x{:010x} (0x{:x})",
                 section->name(), section->file_offset(),
                 section->file_offset() + content.size(), content.size());
      ios_.seekp(section->file_offset());
      ios_.write(content);
    }

    Elf_Off offset_name = 0;
    const auto& it = shstr_map.find(section->name());
    if (it == std::end(shstr_map)) {
      LIEF_WARN("Can't find string offset for section name '{}'", section->name());
    } else {
      offset_name = it->second;
    }

    Elf_Shdr shdr;
    shdr.sh_name      = static_cast<Elf_Word>(offset_name);
    shdr.sh_type      = static_cast<Elf_Word>(section->type());
    shdr.sh_flags     = static_cast<Elf_Word>(section->flags());
    shdr.sh_addr      = static_cast<Elf_Addr>(section->virtual_address());
    shdr.sh_offset    = static_cast<Elf_Off>(section->file_offset());
    shdr.sh_size      = static_cast<Elf_Word>(section->size());
    shdr.sh_link      = static_cast<Elf_Word>(section->link());
    shdr.sh_info      = static_cast<Elf_Word>(section->information());
    shdr.sh_addralign = static_cast<Elf_Word>(section->alignment());
    shdr.sh_entsize   = static_cast<Elf_Word>(section->entry_size());

    // Write Section'header
    if (section_headers_offset > 0) {
      const uint64_t offset = section_headers_offset + i * sizeof(Elf_Shdr);
      LIEF_DEBUG("[Header ] {:20}: 0x{:010x} - 0x{:010x}",
                 section->name(),
                 offset, offset + sizeof(Elf_Shdr));
      ios_.seekp(offset);
      ios_.write_conv<Elf_Shdr>(shdr);
    }
  }
  return ok();
}


template<typename ELF_T>
ok_error_t Builder::build_segments() {
  using Elf_Word = typename ELF_T::Elf_Word;
  using Elf_Addr = typename ELF_T::Elf_Addr;
  using Elf_Off  = typename ELF_T::Elf_Off;
  using Elf_Word = typename ELF_T::Elf_Word;

  using Elf_Phdr = typename ELF_T::Elf_Phdr;
  LIEF_DEBUG("== Build segments ==");

  vector_iostream pheaders(should_swap());
  pheaders.reserve(binary_->segments_.size() * sizeof(Elf_Phdr));
  LIEF_DEBUG("sizeof(PHDR): 0x{:x}", binary_->segments_.size() * sizeof(Elf_Phdr));

  for (const std::unique_ptr<Segment>& segment : binary_->segments_) {
    Elf_Phdr phdr;
    phdr.p_type   = static_cast<Elf_Word>(segment->type());
    phdr.p_flags  = static_cast<Elf_Word>(segment->flags());
    phdr.p_offset = static_cast<Elf_Off>(segment->file_offset());
    phdr.p_vaddr  = static_cast<Elf_Addr>(segment->virtual_address());
    phdr.p_paddr  = static_cast<Elf_Addr>(segment->physical_address());
    phdr.p_filesz = static_cast<Elf_Word>(segment->physical_size());
    phdr.p_memsz  = static_cast<Elf_Word>(segment->virtual_size());
    phdr.p_align  = static_cast<Elf_Word>(segment->alignment());

    pheaders.write_conv<Elf_Phdr>(phdr);
  }

  Segment* phdr_segment = binary_->get(SEGMENT_TYPES::PT_PHDR);
  if (phdr_segment != nullptr) {
    phdr_segment->content(pheaders.raw());
  }

  // Write segment content
  for (const std::unique_ptr<Segment>& segment : binary_->segments_) {
    if (segment->physical_size() > 0) {
      span<const uint8_t> content = segment->content();
      LIEF_DEBUG("[W] {:<13} 0x{:016x}: 0x{:010x} - 0x{:010x} (0x{:x})",
                 to_string(segment->type()), segment->virtual_address(),
                 segment->file_offset(), segment->file_offset() + content.size(),
                 content.size());

      ios_.seekp(segment->file_offset());
      ios_.write(content);
    }
  }

  const Elf_Off segment_header_offset = binary_->header().program_headers_offset();

  LIEF_DEBUG("Write segments header 0x{} -> 0x{}",
             segment_header_offset, segment_header_offset + pheaders.size());
  ios_.seekp(segment_header_offset);
  ios_.write(std::move(pheaders.raw()));
  return ok();
}

template<typename ELF_T>
ok_error_t Builder::build_static_symbols() {
  using Elf_Half = typename ELF_T::Elf_Half;
  using Elf_Word = typename ELF_T::Elf_Word;
  using Elf_Addr = typename ELF_T::Elf_Addr;
  using Elf_Off  = typename ELF_T::Elf_Off;

  using Elf_Sym  = typename ELF_T::Elf_Sym;

  auto* layout = static_cast<ExeLayout*>(layout_.get());

  LIEF_DEBUG("== Build static symbols ==");
  Section* symbol_section = binary_->static_symbols_section();
  if (symbol_section == nullptr) {
    LIEF_ERR("Can't find the .symtab section");
    return make_error_code(lief_errors::file_format_error);
  }
  LIEF_DEBUG(".symtab section: '{}'", symbol_section->name());

  std::stable_sort(std::begin(binary_->static_symbols_), std::end(binary_->static_symbols_),
      [](const std::unique_ptr<Symbol>& lhs, const std::unique_ptr<Symbol>& rhs) {
        return lhs->binding() == SYMBOL_BINDINGS::STB_LOCAL &&
               (
                rhs->binding() == SYMBOL_BINDINGS::STB_GLOBAL ||
                rhs->binding() == SYMBOL_BINDINGS::STB_WEAK
               );
  });

  const auto it_first_exported_symbol =
      std::find_if(std::begin(binary_->static_symbols_), std::end(binary_->static_symbols_),
                   [](const std::unique_ptr<Symbol>& sym) {
                    return sym->is_exported();
                   });

  const auto first_exported_symbol_index =
      static_cast<uint32_t>(std::distance(std::begin(binary_->static_symbols_), it_first_exported_symbol));

  if (first_exported_symbol_index != symbol_section->information()) {
    LIEF_INFO("information of .symtab section changes from {:d} to {:d}",
              symbol_section->information(),
              first_exported_symbol_index);
    symbol_section->information(first_exported_symbol_index);
  }

  if (symbol_section->link() == 0 || symbol_section->link() >= binary_->sections_.size()) {
    LIEF_ERR("Unable to find a string section associated with the symbol section (sh_link)");
    return make_error_code(lief_errors::file_format_error);
  }

  vector_iostream content(should_swap());
  content.reserve(layout->static_sym_size<ELF_T>());

  // On recent compilers, the symtab string table is merged with the section name table
  const std::unordered_map<std::string, size_t>* str_map = nullptr;
  if (layout->is_strtab_shared_shstrtab()) {
    str_map = &layout->shstr_map();
  } else {
    str_map = &layout->strtab_map();
  }

  for (const std::unique_ptr<Symbol>& symbol : binary_->static_symbols_) {
    const std::string& name = symbol->name();

    Elf_Off offset_name = 0;
    const auto it = str_map->find(name);
    if (it == std::end(*str_map)) {
      LIEF_ERR("Can't find string offset for static symbol name '{}'", name);
    } else {
      offset_name = it->second;
    }

    Elf_Sym sym_hdr;
    memset(&sym_hdr, 0, sizeof(Elf_Sym));
    sym_hdr.st_name  = static_cast<Elf_Word>(offset_name);
    sym_hdr.st_info  = static_cast<unsigned char>(symbol->information());
    sym_hdr.st_other = static_cast<unsigned char>(symbol->other());
    sym_hdr.st_shndx = static_cast<Elf_Half>(symbol->shndx());
    sym_hdr.st_value = static_cast<Elf_Addr>(symbol->value());
    sym_hdr.st_size  = static_cast<Elf_Word>(symbol->size());

    content.write_conv<Elf_Sym>(sym_hdr);
  }
  symbol_section->content(std::move(content.raw()));
  return ok();
}

template<typename ELF_T>
ok_error_t Builder::build_dynamic_section() {
  using Elf_Addr   = typename ELF_T::Elf_Addr;
  using Elf_Sxword = typename ELF_T::Elf_Sxword;
  using Elf_Xword  = typename ELF_T::Elf_Xword;
  using Elf_Dyn    = typename ELF_T::Elf_Dyn;

  LIEF_DEBUG("[+] Building .dynamic");

  const auto& dynstr_map = static_cast<ExeLayout*>(layout_.get())->dynstr_map();
  vector_iostream dynamic_table_raw;
  for (std::unique_ptr<DynamicEntry>& entry : binary_->dynamic_entries_) {

    switch (entry->tag()) {
      case DYNAMIC_TAGS::DT_NEEDED:
        {
          const std::string& name = entry->as<DynamicEntryLibrary>()->name();
          const auto& it = dynstr_map.find(name);
          if (it == std::end(dynstr_map)) {
            LIEF_ERR("Can't find string offset in .dynstr for {}", name);
            break;
          }
          entry->value(it->second);
          break;
        }

      case DYNAMIC_TAGS::DT_SONAME:
        {
          const std::string& name = entry->as<DynamicSharedObject>()->name();
          const auto& it = dynstr_map.find(name);
          if (it == std::end(dynstr_map)) {
            LIEF_ERR("Can't find string offset in .dynstr for {}", name);
            break;
          }
          entry->value(it->second);
          break;
        }

      case DYNAMIC_TAGS::DT_RPATH:
        {
          const std::string& name = entry->as<DynamicEntryRpath>()->name();
          const auto& it = dynstr_map.find(name);
          if (it == std::end(dynstr_map)) {
            LIEF_ERR("Can't find string offset in .dynstr for {}", name);
            break;
          }
          entry->value(it->second);
          break;
        }

      case DYNAMIC_TAGS::DT_RUNPATH:
        {
          const std::string& name = entry->as<DynamicEntryRunPath>()->name();
          const auto& it = dynstr_map.find(name);
          if (it == std::end(dynstr_map)) {
            LIEF_ERR("Can't find string offset in .dynstr for {}", name);
            break;
          }
          entry->value(it->second);
          break;
        }

      case DYNAMIC_TAGS::DT_INIT_ARRAY:
        {
          if (config_.init_array) {
            DynamicEntry* dt_array_size = binary_->get(DYNAMIC_TAGS::DT_INIT_ARRAYSZ);
            if (dt_array_size == nullptr) {
              LIEF_ERR("Can't find the DT_INIT_ARRAYSZ / .init_array");
              break;
            }
            const std::vector<uint64_t>& array = entry->as<DynamicEntryArray>()->array();
            std::vector<uint8_t> array_content(array.size() * sizeof(Elf_Addr), 0);

            auto* raw_array = reinterpret_cast<Elf_Addr*>(array_content.data());
            for (size_t i = 0; i < array.size(); ++i) {
              raw_array[i] = static_cast<Elf_Addr>(array[i]);
            }

            dt_array_size->value(array_content.size());
            binary_->patch_address(entry->value(), array_content);
          }
          break;
        }

      case DYNAMIC_TAGS::DT_FINI_ARRAY:
        {
          if (config_.fini_array) {
            DynamicEntry* dt_array_size = binary_->get(DYNAMIC_TAGS::DT_FINI_ARRAYSZ);
            if (dt_array_size == nullptr) {
              LIEF_ERR("Can't find the DT_FINI_ARRAYSZ / .fini_array");
              break;
            }

            const std::vector<uint64_t>& array = entry->as<DynamicEntryArray>()->array();
            std::vector<uint8_t> array_content(array.size() * sizeof(Elf_Addr), 0);

            auto* raw_array = reinterpret_cast<Elf_Addr*>(array_content.data());
            for (size_t i = 0; i < array.size(); ++i) {
              raw_array[i] = static_cast<Elf_Addr>(array[i]);
            }

            dt_array_size->value(array_content.size());
            binary_->patch_address(entry->value(), array_content);
          }
          break;
        }

      case DYNAMIC_TAGS::DT_PREINIT_ARRAY:
        {
          if (config_.fini_array) {
            DynamicEntry* dt_array_size = binary_->get(DYNAMIC_TAGS::DT_PREINIT_ARRAYSZ);
            if (dt_array_size == nullptr) {
              LIEF_ERR("Can't find the DT_PREINIT_ARRAYSZ / .preinit_array");
              break;
            }


            const std::vector<uint64_t>& array = entry->as<DynamicEntryArray>()->array();
            std::vector<uint8_t> array_content(array.size() * sizeof(Elf_Addr), 0);

            auto* raw_array = reinterpret_cast<Elf_Addr*>(array_content.data());
            for (size_t i = 0; i < array.size(); ++i) {
              raw_array[i] = static_cast<Elf_Addr>(array[i]);
            }

            dt_array_size->value(array_content.size());
            binary_->patch_address(entry->value(), array_content);
          }
          break;
        }

      default:
        {
          // TODO(romain): Support DT_AUXILIARY
        }
    }

    Elf_Dyn dynhdr;
    dynhdr.d_tag      = static_cast<Elf_Sxword>(entry->tag());
    dynhdr.d_un.d_val = static_cast<Elf_Xword>(entry->value());

    dynamic_table_raw.write_conv<Elf_Dyn>(dynhdr);
  }

  // Update the PT_DYNAMIC segment
  Segment* dynamic_seg = binary_->get(SEGMENT_TYPES::PT_DYNAMIC);
  if (dynamic_seg == nullptr) {
    LIEF_ERR("Can't find the PT_DYNAMIC segment");
    return make_error_code(lief_errors::file_format_error);
  }
  std::vector<uint8_t> raw = dynamic_table_raw.raw();
  dynamic_seg->physical_size(raw.size());
  dynamic_seg->virtual_size(raw.size());
  dynamic_seg->content(std::move(raw));
  return ok();
}


template<typename ELF_T>
ok_error_t Builder::build_symbol_hash() {
  LIEF_DEBUG("== Build SYSV Hash ==");
  DynamicEntry* dt_hash = binary_->get(DYNAMIC_TAGS::DT_HASH);

  if (dt_hash == nullptr) {
    LIEF_ERR("Can't find the SYSV hash section");
    return make_error_code(lief_errors::not_found);
  }

  const SysvHash* sysv = binary_->sysv_hash();
  if (sysv == nullptr) {
    LIEF_ERR("Can't find the original SYSV hash in the binary");
    return make_error_code(lief_errors::not_found);
  }


  uint32_t nbucket = sysv->nbucket();
  uint32_t nchain  = static_cast<ExeLayout*>(layout_.get())->sysv_nchain();

  if (nbucket == 0) {
    LIEF_ERR("sysv.nbucket is 0");
    return make_error_code(lief_errors::build_error);
  }

  const size_t buckets_limits = nbucket + nchain + 2;
  std::vector<uint8_t> new_hash_table(buckets_limits * sizeof(uint32_t), 0);
  auto* new_hash_table_ptr = reinterpret_cast<uint32_t*>(new_hash_table.data());

  new_hash_table_ptr[0] = nbucket;
  new_hash_table_ptr[1] = nchain;

  uint32_t* bucket = &new_hash_table_ptr[2];
  uint32_t* chain  = &new_hash_table_ptr[2 + nbucket];
  uint32_t idx = 0;
  for (const std::unique_ptr<Symbol>& symbol : binary_->dynamic_symbols_) {
    uint32_t hash = binary_->type_ == ELF_CLASS::ELFCLASS32 ?
                    hash32(symbol->name().c_str()) :
                    hash64(symbol->name().c_str());

    const size_t bucket_idx = hash % nbucket;
    if (bucket_idx >= buckets_limits) {
      LIEF_WARN("Bucket {} is out of range", bucket_idx);
      continue;
    }
    if (bucket[bucket_idx] == 0) {
      bucket[hash % nbucket] = idx;
    } else {
      uint32_t value = bucket[hash % nbucket];
      while (chain[value] != 0) {
        value = chain[value];
        if (value >= (new_hash_table.size() / sizeof(uint32_t))) {
          LIEF_ERR("Symbol out-of-bound {}", symbol->name());
          return make_error_code(lief_errors::file_format_error);
        }
      }
      chain[value] = idx;
    }
    ++idx;
  }

  // to be improved...?
  if (should_swap()) {
    for (size_t i = 0; i < buckets_limits; i++) {
      Convert::swap_endian(&new_hash_table_ptr[i]);
    }
  }
  binary_->patch_address(dt_hash->value(), std::move(new_hash_table));
  return ok();
}


template<typename ELF_T>
ok_error_t Builder::build_hash_table() {
  LIEF_DEBUG("== Build hash table ==");

  bool has_error = false;
  if (config_.dt_hash && binary_->has(DYNAMIC_TAGS::DT_HASH)) {
    if (!build_symbol_hash<ELF_T>()) {
      LIEF_ERR("Building the new SYSV Hash section failed");
      has_error = true;
    }
  }

  if (config_.gnu_hash) {
    if (const DynamicEntry* entry = binary_->get(DYNAMIC_TAGS::DT_GNU_HASH)) {
      binary_->patch_address(entry->value(), static_cast<ExeLayout*>(layout_.get())->raw_gnuhash());
    }
  }
  if (has_error) {
    return make_error_code(lief_errors::build_error);
  }
  return ok();
}


template<typename ELF_T>
ok_error_t Builder::build_obj_symbols() {
  using Elf_Half = typename ELF_T::Elf_Half;
  using Elf_Word = typename ELF_T::Elf_Word;
  using Elf_Addr = typename ELF_T::Elf_Addr;
  using Elf_Off  = typename ELF_T::Elf_Off;

  using Elf_Sym  = typename ELF_T::Elf_Sym;
  const auto* layout = static_cast<const ObjectFileLayout*>(layout_.get());
  const std::unordered_map<std::string, size_t>* str_map = nullptr;

  if (layout->is_strtab_shared_shstrtab()) {
    str_map = &layout->shstr_map();
  } else {
    str_map = &layout->strtab_map();
  }

  // Find the section associated with the address
  Section* symbol_table_section = binary_->get(ELF_SECTION_TYPES::SHT_SYMTAB);
  if (symbol_table_section == nullptr) {
    LIEF_ERR("Can't find the .symtab section");
    return make_error_code(lief_errors::file_format_error);
  }

  // Build symbols
  vector_iostream symbol_table_raw(should_swap());
  for (const std::unique_ptr<Symbol>& symbol : binary_->static_symbols_) {
    const std::string& name = symbol->name();
    const auto offset_it = str_map->find(name);
    if (offset_it == std::end(*str_map)) {
      LIEF_ERR("Unable to find the symbol offset for '{}' in the string table", name);
      continue;
    }

    const auto name_offset = static_cast<Elf_Off>(offset_it->second);

    Elf_Sym sym_header;
    memset(&sym_header, 0, sizeof(Elf_Sym));

    sym_header.st_name  = static_cast<Elf_Word>(name_offset);
    sym_header.st_info  = static_cast<unsigned char>(symbol->information());
    sym_header.st_other = static_cast<unsigned char>(symbol->other());
    sym_header.st_shndx = static_cast<Elf_Half>(symbol->shndx());
    sym_header.st_value = static_cast<Elf_Addr>(symbol->value());
    sym_header.st_size  = static_cast<Elf_Addr>(symbol->size());

    symbol_table_raw.write_conv(sym_header);
  }
  symbol_table_section->content(std::move(symbol_table_raw.raw()));
  return ok();
}

template<typename ELF_T>
ok_error_t Builder::build_dynamic_symbols() {
  using Elf_Half = typename ELF_T::Elf_Half;
  using Elf_Word = typename ELF_T::Elf_Word;
  using Elf_Addr = typename ELF_T::Elf_Addr;
  using Elf_Off  = typename ELF_T::Elf_Off;
  using Elf_Word = typename ELF_T::Elf_Word;

  using Elf_Sym  = typename ELF_T::Elf_Sym;
  LIEF_DEBUG("[+] Build .dynsym symbols");

  const auto& dynstr_map = static_cast<ExeLayout*>(layout_.get())->dynstr_map();

  // Find useful sections
  // ====================
  DynamicEntry* dt_symtab = binary_->get(DYNAMIC_TAGS::DT_SYMTAB);
  if (dt_symtab == nullptr) {
    LIEF_ERR("Can't find the DT_SYMTAB entry");
    return make_error_code(lief_errors::not_found);
  }
  Elf_Addr symbol_table_va = dt_symtab->value();



  // Build symbols
  vector_iostream symbol_table_raw(should_swap());
  for (const std::unique_ptr<Symbol>& symbol : binary_->dynamic_symbols_) {
    const std::string& name = symbol->name();
    const auto& offset_it = dynstr_map.find(name);
    if (offset_it == std::end(dynstr_map)) {
      LIEF_ERR("Unable to find the symbol offset for '{}' in the string table", name);
      continue;
    }

    const auto name_offset = static_cast<Elf_Off>(offset_it->second);

    Elf_Sym sym_header;

    memset(&sym_header, 0, sizeof(sym_header));

    sym_header.st_name  = static_cast<Elf_Word>(name_offset);
    sym_header.st_info  = static_cast<unsigned char>(symbol->information());
    sym_header.st_other = static_cast<unsigned char>(symbol->other());
    sym_header.st_shndx = static_cast<Elf_Half>(symbol->shndx());
    sym_header.st_value = static_cast<Elf_Addr>(symbol->value());
    sym_header.st_size  = static_cast<Elf_Addr>(symbol->size());

    symbol_table_raw.write_conv(sym_header);
  }
  binary_->patch_address(symbol_table_va, symbol_table_raw.raw());
  return ok();
}

template<typename ELF_T>
ok_error_t Builder::build_section_relocations() {
  using Elf_Addr   = typename ELF_T::Elf_Addr;
  using Elf_Xword  = typename ELF_T::Elf_Xword;
  using Elf_Sxword = typename ELF_T::Elf_Sxword;

  using Elf_Rela   = typename ELF_T::Elf_Rela;
  using Elf_Rel    = typename ELF_T::Elf_Rel;
  LIEF_DEBUG("[+] Building relocations");

  auto* layout = static_cast<ObjectFileLayout*>(layout_.get());

  Binary::it_object_relocations object_relocations = binary_->object_relocations();
  const bool is_rela = object_relocations[0].is_rela();
  std::unordered_map<Section*, vector_iostream> section_content;

  const ObjectFileLayout::sections_reloc_map_t& sec_relo_map = layout->sections_reloc_map();
  for (const auto& p : layout->relocation_map()) {
    Section* section = p.first;
    std::vector<Relocation*> relocs = p.second;
    // sort relocations by offset. It is not required by the ELF standard but some linkers (like ld)
    // rely on this kind of sort for sections such as .eh_frame;
    std::sort(std::begin(relocs), std::end(relocs),
              [] (const Relocation* lhs, const Relocation* rhs) {
                return lhs->address() < rhs->address();
              });
    for (const Relocation* reloc : relocs) {
      Section* reloc_section = sec_relo_map.at(section);
      uint32_t symidx = 0;
      const Symbol* sym = reloc->symbol();
      if (sym != nullptr) {
        const auto it_sym = std::find_if(std::begin(binary_->static_symbols_), std::end(binary_->static_symbols_),
                                         [sym] (const std::unique_ptr<Symbol>& s) {
                                           return s.get() == sym;
                                         });
        if (it_sym == std::end(binary_->static_symbols_)) {
          LIEF_WARN("Can find the relocation's symbol '{}'", sym->name());
          continue;
        }

        symidx = static_cast<uint32_t>(std::distance(std::begin(binary_->static_symbols_), it_sym));
      }

      Elf_Xword info = 0;
      if (std::is_same<ELF_T, details::ELF32>::value) {
        info = (static_cast<Elf_Xword>(symidx) << 8) | reloc->type();
      } else {
        // NOTE: To suppress a warning we require a cast here, this path is not constexpr but only uses Elf64_Xword
        info = (static_cast<details::ELF64::Elf_Xword>(symidx) << 32) | (reloc->type() & 0xffffffffL);
      }
      
      if (is_rela) {
        Elf_Rela relahdr;
        relahdr.r_offset = static_cast<Elf_Addr>(reloc->address());
        relahdr.r_info   = static_cast<Elf_Xword>(info);
        relahdr.r_addend = static_cast<Elf_Sxword>(reloc->addend());
        section_content[reloc_section].write<Elf_Rela>(relahdr);
      } else {
        Elf_Rel relhdr;
        relhdr.r_offset = static_cast<Elf_Addr>(reloc->address());
        relhdr.r_info   = static_cast<Elf_Xword>(info);
        section_content[reloc_section].write<Elf_Rel>(relhdr);
      }
    }
  }

  for (auto& p : section_content) {
    Section* sec = p.first;
    vector_iostream& ios = p.second;
    LIEF_DEBUG("Fill section {} with 0x{:x} bytes", sec->name(), ios.raw().size());
    sec->content(ios.raw());
  }
  return ok();
}

template<typename ELF_T>
ok_error_t Builder::build_dynamic_relocations() {
  using Elf_Addr   = typename ELF_T::Elf_Addr;
  using Elf_Xword  = typename ELF_T::Elf_Xword;
  using Elf_Sxword = typename ELF_T::Elf_Sxword;

  using Elf_Rela   = typename ELF_T::Elf_Rela;
  using Elf_Rel    = typename ELF_T::Elf_Rel;

  Binary::it_dynamic_relocations dynamic_relocations = binary_->dynamic_relocations();
  if (dynamic_relocations.empty()) {
    return ok();
  }

  LIEF_DEBUG("[+] Building dynamic relocations");
  DynamicEntry* dt_reloc   = nullptr;
  DynamicEntry* dt_relocsz = nullptr;

  DynamicEntry* dt_rela = binary_->get(DYNAMIC_TAGS::DT_RELA);

  const bool is_rela = dt_rela != nullptr;
  if (dt_rela != nullptr) {
    dt_reloc   = dt_rela;
    dt_relocsz = binary_->get(DYNAMIC_TAGS::DT_RELASZ);
  } else {
    // Fallback on relation type REL
    dt_reloc   = binary_->get(DYNAMIC_TAGS::DT_REL);
    dt_relocsz = binary_->get(DYNAMIC_TAGS::DT_RELSZ);
  }


  if (dt_reloc == nullptr) {
    LIEF_ERR("Unable to find the DT_REL/DT_RELA");
    return make_error_code(lief_errors::not_found);
  }

  if (dt_relocsz == nullptr) {
    LIEF_ERR("Unable to find the DT_RELSZ/DT_RELASZ");
    return make_error_code(lief_errors::not_found);
  }


  vector_iostream content(should_swap());
  for (const Relocation& relocation : binary_->dynamic_relocations()) {

    // look for symbol index
    uint32_t idx = 0;
    const Symbol* symbol = relocation.symbol();
    if (symbol != nullptr) {
      const std::string& name = symbol->name();
      const auto it_name = std::find_if(
          std::begin(binary_->dynamic_symbols_), std::end(binary_->dynamic_symbols_),
          [&name] (const std::unique_ptr<Symbol>& s) {
            return s->name() == name;
          });

      if (it_name == std::end(binary_->dynamic_symbols_)) {
        LIEF_ERR("Unable to find the symbol associated with the relocation");
        return make_error_code(lief_errors::not_found);
      }

      idx = static_cast<uint32_t>(std::distance(std::begin(binary_->dynamic_symbols_), it_name));
    }

    uint32_t info = relocation.info();
    if (idx > 0) {
      info = idx;
    }

    Elf_Xword r_info = 0;
    if (std::is_same<ELF_T, details::ELF32>::value) {
      r_info = (static_cast<Elf_Xword>(info) << 8) | relocation.type();
    } else {
      // NOTE: To suppress a warning we require a cast here, this path is not constexpr but only uses Elf64_Xword
      r_info = (static_cast<details::ELF64::Elf_Xword>(info) << 32) | (relocation.type() & 0xffffffffL);
    }


    if (is_rela) {
      Elf_Rela relahdr;
      relahdr.r_offset = static_cast<Elf_Addr>(relocation.address());
      relahdr.r_info   = static_cast<Elf_Xword>(r_info);
      relahdr.r_addend = static_cast<Elf_Sxword>(relocation.addend());

      content.write_conv<Elf_Rela>(relahdr);
    } else {
      Elf_Rel relhdr;
      relhdr.r_offset = static_cast<Elf_Addr>(relocation.address());
      relhdr.r_info   = static_cast<Elf_Xword>(r_info);

      content.write_conv<Elf_Rel>(relhdr);
    }
  }
  binary_->patch_address(dt_reloc->value(), content.raw());
  return ok();
}

template<typename ELF_T>
ok_error_t Builder::build_pltgot_relocations() {
  using Elf_Addr   = typename ELF_T::Elf_Addr;
  using Elf_Xword  = typename ELF_T::Elf_Xword;
  using Elf_Sxword = typename ELF_T::Elf_Sxword;

  using Elf_Rela   = typename ELF_T::Elf_Rela;
  using Elf_Rel    = typename ELF_T::Elf_Rel;

  Binary::it_pltgot_relocations pltgot_relocations = binary_->pltgot_relocations();
  if (pltgot_relocations.empty()) {
    return ok();
  }

  LIEF_DEBUG("[+] Building .plt.got relocations");

  bool is_rela = false;
  DynamicEntry* dt_pltrel = binary_->get(DYNAMIC_TAGS::DT_PLTREL);
  if (dt_pltrel != nullptr) {
    is_rela = dt_pltrel->value() == static_cast<uint64_t>(DYNAMIC_TAGS::DT_RELA);
  }
  DynamicEntry* dt_jmprel   = binary_->get(DYNAMIC_TAGS::DT_JMPREL);
  DynamicEntry* dt_pltrelsz = binary_->get(DYNAMIC_TAGS::DT_PLTRELSZ);
  if (dt_jmprel == nullptr) {
    LIEF_ERR("Unable to find the DT_JMPREL entry");
    return make_error_code(lief_errors::not_found);
  }

  if (dt_pltrelsz == nullptr) {
    LIEF_ERR("Unable to find the DT_PLTRELSZ entry");
    return make_error_code(lief_errors::not_found);
  }

  vector_iostream content(should_swap()); // Section's content
  for (const Relocation& relocation : binary_->pltgot_relocations()) {
    uint32_t idx = 0;
    const Symbol* symbol = relocation.symbol();
    if (symbol != nullptr) {
      // look for symbol index
      const std::string& name = symbol->name();
      const auto& it_name = std::find_if(
          std::begin(binary_->dynamic_symbols_), std::end(binary_->dynamic_symbols_),
          [&name] (const std::unique_ptr<Symbol>& s) {
            return s->name() == name;
          });

      if (it_name == std::end(binary_->dynamic_symbols_)) {
        LIEF_ERR("Unable to find the symbol associated with the relocation");
        return make_error_code(lief_errors::not_found);
      }

      idx = static_cast<uint32_t>(std::distance(std::begin(binary_->dynamic_symbols_), it_name));
    }

    Elf_Xword info = 0;
    if (std::is_same<ELF_T, details::ELF32>::value) {
      info = (static_cast<Elf_Xword>(idx) << 8) | relocation.type();
    } else {
      // NOTE: To suppress a warning we require a cast here, this path is not constexpr but only uses Elf64_Xword
      info = (static_cast<details::ELF64::Elf_Xword>(idx) << 32) | (relocation.type() & 0xffffffffL);
    }

    if (is_rela) {
      Elf_Rela relahdr;
      relahdr.r_offset = static_cast<Elf_Addr>(relocation.address());
      relahdr.r_info   = static_cast<Elf_Xword>(info);
      relahdr.r_addend = static_cast<Elf_Sxword>(relocation.addend());

      content.write_conv<Elf_Rela>(relahdr);
    } else {
      Elf_Rel relhdr;
      relhdr.r_offset = static_cast<Elf_Addr>(relocation.address());
      relhdr.r_info   = static_cast<Elf_Xword>(info);

      content.write_conv<Elf_Rel>(relhdr);
    }
  }
  binary_->patch_address(dt_jmprel->value(), content.raw());
  return ok();
}


template<typename ELF_T>
ok_error_t Builder::build_symbol_requirement() {
  using Elf_Half    = typename ELF_T::Elf_Half;
  using Elf_Word    = typename ELF_T::Elf_Word;
  using Elf_Off     = typename ELF_T::Elf_Off;
  using Elf_Addr    = typename ELF_T::Elf_Addr;

  using Elf_Verneed = typename ELF_T::Elf_Verneed;
  using Elf_Vernaux = typename ELF_T::Elf_Vernaux;
  LIEF_DEBUG("[+] Building symbol requirement");

  DynamicEntry* dt_verneed = binary_->get(DYNAMIC_TAGS::DT_VERNEED);
  if (dt_verneed == nullptr) {
    LIEF_ERR("Can't find DT_VERNEED");
    return make_error_code(lief_errors::not_found);
  }

  DynamicEntry* dt_verneednum = binary_->get(DYNAMIC_TAGS::DT_VERNEEDNUM);
  if (dt_verneednum == nullptr) {
    LIEF_ERR("Can't find DT_VERNEEDNUM");
    return make_error_code(lief_errors::not_found);
  }
  const Elf_Addr svr_address = dt_verneed->value();
  const auto svr_nb          = static_cast<uint32_t>(dt_verneednum->value());

  if (svr_nb != binary_->symbol_version_requirements_.size()) {
    LIEF_WARN("The number of symbol version requirement "
              "entries in the binary differ from the value in DT_VERNEEDNUM");
  }

  vector_iostream svr_raw(should_swap());

  uint32_t svr_idx = 0;
  const auto& sym_name_offset = static_cast<ExeLayout*>(layout_.get())->dynstr_map();
  for (SymbolVersionRequirement& svr: binary_->symbols_version_requirement()) {
    const std::string& name = svr.name();

    Elf_Off name_offset = 0;
    const auto& it_name_offset = sym_name_offset.find(name);
    if (it_name_offset != std::end(sym_name_offset)) {
      name_offset = it_name_offset->second;
    } else {
      LIEF_ERR("Can't find dynstr offset for '{}'", name);
      continue;
    }

    SymbolVersionRequirement::it_aux_requirement svars = svr.auxiliary_symbols();

    Elf_Off next_symbol_offset = 0;
    if (svr_idx < (binary_->symbol_version_requirements_.size() - 1)) {
      next_symbol_offset = sizeof(Elf_Verneed) + svars.size() * sizeof(Elf_Vernaux);
    }

    Elf_Verneed header;
    header.vn_version = static_cast<Elf_Half>(svr.version());
    header.vn_cnt     = static_cast<Elf_Half>(svars.size());
    header.vn_file    = static_cast<Elf_Word>(name_offset);
    header.vn_aux     = static_cast<Elf_Word>(!svars.empty() ? sizeof(Elf_Verneed) : 0);
    header.vn_next    = static_cast<Elf_Word>(next_symbol_offset);

    svr_raw.write_conv<Elf_Verneed>(header);


    uint32_t svar_idx = 0;
    for (SymbolVersionAuxRequirement& svar : svars) {
      const std::string& svar_name = svar.name();

      Elf_Off svar_name_offset = 0;

      const auto& it_name_offset = sym_name_offset.find(svar_name);
      if (it_name_offset != std::end(sym_name_offset)) {
        svar_name_offset = it_name_offset->second;
      } else {
        LIEF_ERR("Can't find dynstr offset for '{}'", name);
        continue;
      }
      uint32_t new_hash = 0;
      if (std::is_same<ELF_T, details::ELF32>::value) {
        new_hash = hash32(svar_name.c_str());
      } else {
        new_hash = hash64(svar_name.c_str());
      }
      if (new_hash != svar.hash()) {
        LIEF_WARN("Hash value for {} does not match. Updating ...", svar_name);
        svar.hash(new_hash);
      }

      Elf_Vernaux aux_header;
      aux_header.vna_hash  = static_cast<Elf_Word>(svar.hash());
      aux_header.vna_flags = static_cast<Elf_Half>(svar.flags());
      aux_header.vna_other = static_cast<Elf_Half>(svar.other());
      aux_header.vna_name  = static_cast<Elf_Word>(svar_name_offset);
      aux_header.vna_next  = static_cast<Elf_Word>(svar_idx < (svars.size() - 1) ? sizeof(Elf_Vernaux) : 0);

      svr_raw.write_conv<Elf_Vernaux>(aux_header);

      ++svar_idx;
    }
    ++svr_idx;
  }

  binary_->patch_address(svr_address, svr_raw.raw());
  return ok();
}

template<typename ELF_T>
ok_error_t Builder::build_symbol_definition() {
  using Elf_Half    = typename ELF_T::Elf_Half;
  using Elf_Word    = typename ELF_T::Elf_Word;
  using Elf_Addr    = typename ELF_T::Elf_Addr;
  using Elf_Off     = typename ELF_T::Elf_Off;

  using Elf_Verdef  = typename ELF_T::Elf_Verdef;
  using Elf_Verdaux = typename ELF_T::Elf_Verdaux;

  LIEF_DEBUG("[+] Building symbol definition");
  DynamicEntry* dt_verdef = binary_->get(DYNAMIC_TAGS::DT_VERDEF);
  if (dt_verdef == nullptr) {
    LIEF_ERR("Can't find DT_VERDEF");
    return make_error_code(lief_errors::not_found);
  }

  DynamicEntry* dt_verdefnum = binary_->get(DYNAMIC_TAGS::DT_VERDEFNUM);
  if (dt_verdef == nullptr) {
    LIEF_ERR("Can't find DT_VERDEFNUM");
    return make_error_code(lief_errors::not_found);
  }

  const Elf_Addr svd_va    = dt_verdef->value();
  const uint32_t svd_nb    = dt_verdefnum->value();

  if (svd_nb != binary_->symbol_version_definition_.size()) {
    LIEF_WARN("The number of symbol version definition entries "
              "in the binary differ from the value in DT_VERDEFNUM");
  }

  vector_iostream svd_raw(should_swap());

  uint32_t svd_idx = 0;
  const auto& sym_name_offset = static_cast<ExeLayout*>(layout_.get())->dynstr_map();
  for (const SymbolVersionDefinition& svd: binary_->symbols_version_definition()) {

    SymbolVersionDefinition::it_const_version_aux svas = svd.symbols_aux();

    Elf_Off next_symbol_offset = 0;

    if (svd_idx < (svd_nb - 1)) {
      next_symbol_offset = sizeof(Elf_Verdef) + svas.size() * sizeof(Elf_Verdaux);
    }

    Elf_Verdef header;
    header.vd_version = static_cast<Elf_Half>(svd.version());
    header.vd_flags   = static_cast<Elf_Half>(svd.flags());
    header.vd_ndx     = static_cast<Elf_Half>(svd.ndx());
    header.vd_cnt     = static_cast<Elf_Half>(svas.size());
    header.vd_hash    = static_cast<Elf_Word>(svd.hash());
    header.vd_aux     = static_cast<Elf_Word>(!svas.empty() ? sizeof(Elf_Verdef) : 0);
    header.vd_next    = static_cast<Elf_Word>(next_symbol_offset);

    svd_raw.write_conv<Elf_Verdef>(header);


    uint32_t sva_idx = 0;
    for (const SymbolVersionAux& sva : svas) {
      const std::string& sva_name = sva.name();

      Elf_Off sva_name_offset = 0;
      const auto& it_name_offset = sym_name_offset.find(sva_name);
      if (it_name_offset != std::end(sym_name_offset)) {
        sva_name_offset = it_name_offset->second;
      } else {
        LIEF_ERR("Can't find dynstr offset for '{}'", sva_name);
        continue;
      }

      Elf_Verdaux aux_header;
      aux_header.vda_name  = static_cast<Elf_Word>(sva_name_offset);
      aux_header.vda_next  = static_cast<Elf_Word>(sva_idx < (svas.size() - 1) ? sizeof(Elf_Verdaux) : 0);

      svd_raw.write_conv<Elf_Verdaux>(aux_header);

      ++sva_idx;
    }
    ++svd_idx;
  }

  binary_->patch_address(svd_va, svd_raw.raw());
  return ok();
}

template<typename ELF_T>
ok_error_t Builder::build_interpreter() {
  if (!config_.interpreter) {
    return ok();
  }
  LIEF_DEBUG("[+] Building Interpreter");
  const std::string& inter_str = binary_->interpreter();
  Segment* interp_segment = binary_->get(SEGMENT_TYPES::PT_INTERP);
  if (interp_segment == nullptr) {
    LIEF_ERR("Can't find a PT_INTERP segment");
    return make_error_code(lief_errors::not_found);
  }
  const char* inter_cstr = inter_str.c_str();
  interp_segment->content({inter_cstr, inter_cstr + inter_str.size() + 1});
  return ok();
}

template<typename ELF_T>
ok_error_t Builder::build_notes() {
  if (!config_.notes) {
    return ok();
  }

  LIEF_DEBUG("== Building notes ==");
  Segment* note_segment = binary_->get(SEGMENT_TYPES::PT_NOTE);
  if (note_segment == nullptr) {
    LIEF_ERR("Can't find the PT_NOTE segment");
    return make_error_code(lief_errors::not_found);
  }
  // Clear the original content of the segment
  note_segment->content(std::vector<uint8_t>(note_segment->physical_size(), 0));

  note_segment->content(static_cast<ExeLayout*>(layout_.get())->raw_notes());

  //TODO: .note.netbds etc
  if (binary_->header().file_type() == E_TYPE::ET_CORE) {
    LIEF_WARN("Building note for coredump is not supported yet");
    return make_error_code(lief_errors::not_supported);
  }

  // Track the list of the sections we wrote
  // NOTE(romain): it is only used by the function build() itself but
  //               to avoid creating an instance field, we create this
  //               variable in the scode of this function
  std::set<Section*> sections;
  for (Note& note: binary_->notes()) {
    build(note, sections);
  }
  return ok();
}

template<class ELF_T>
ok_error_t Builder::build_symbol_version() {

  LIEF_DEBUG("[+] Building symbol version");

  if (binary_->symbol_version_table_.size() != binary_->dynamic_symbols_.size()) {
    LIEF_WARN("The number of symbol version is different from the number of dynamic symbols {} != {}",
              binary_->symbol_version_table_.size(), binary_->dynamic_symbols_.size());
  }

  DynamicEntry* dt_versym = binary_->get(DYNAMIC_TAGS::DT_VERSYM);
  if (dt_versym == nullptr) {
    LIEF_ERR("Can't find DT_VERSYM entry");
    return make_error_code(lief_errors::not_found);
  }
  const uint64_t sv_address = dt_versym->value();

  vector_iostream sv_raw(should_swap());
  sv_raw.reserve(binary_->symbol_version_table_.size() * sizeof(uint16_t));

  //for (const SymbolVersion* sv : binary_->symbol_version_table_) {
  for (const std::unique_ptr<Symbol>& symbol : binary_->dynamic_symbols_) {
    const SymbolVersion* sv = symbol->symbol_version();
    if (sv == nullptr) {
      LIEF_ERR("No version associated with the symbol {}", symbol->name());
      return make_error_code(lief_errors::not_found);
    }
    const uint16_t value = sv->value();
    sv_raw.write_conv<uint16_t>(value);
  }
  binary_->patch_address(sv_address, sv_raw.raw());
  return ok();
}


template<class ELF_T>
ok_error_t Builder::build_overlay() {
  if (binary_->overlay_.empty()) {
    return ok();
  }
  const Binary::overlay_t& overlay = binary_->overlay();
  const uint64_t last_offset = binary_->eof_offset();

  if (last_offset > 0) {
    ios_.seekp(last_offset);
    ios_.write(overlay);
  }
  return ok();
}

} // namespace ELF
} // namespace LIEF
