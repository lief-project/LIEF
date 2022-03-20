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
#include <numeric>

#include "ELF/DataHandler/Handler.hpp"
#include "ELF/DataHandler/Node.hpp"
#include "ELF/Structures.hpp"
#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/DynamicEntry.hpp"
#include "LIEF/ELF/EnumToString.hpp"
#include "LIEF/ELF/Relocation.hpp"
#include "LIEF/ELF/Section.hpp"
#include "LIEF/ELF/Segment.hpp"
#include "LIEF/ELF/enums.hpp"
#include "logging.hpp"

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#else
#define getpagesize() 0x1000
#endif

namespace LIEF {
namespace ELF {

// ===============
// ARM Relocations
// ===============
template <>
void Binary::patch_relocations<ARCH::EM_ARM>(uint64_t from, uint64_t shift) {
  for (Relocation& relocation : relocations()) {
    if (relocation.address() >= from) {
      // shift_code(relocation.address(), shift, relocation.size() / 8);
      relocation.address(relocation.address() + shift);
    }

    const auto type = static_cast<RELOC_ARM>(relocation.type());

    switch (type) {
      case RELOC_ARM::R_ARM_JUMP_SLOT:
      case RELOC_ARM::R_ARM_RELATIVE:
      case RELOC_ARM::R_ARM_GLOB_DAT:
      case RELOC_ARM::R_ARM_IRELATIVE: {
        LIEF_DEBUG("Patch addend of {}", relocation);
        patch_addend<uint32_t>(relocation, from, shift);
        break;
      }

      default: {
        LIEF_DEBUG("Relocation {} is not patched", to_string(type));
      }
    }
  }
}

// ===================
// AARCH64 Relocations
// ===================
template <>
void Binary::patch_relocations<ARCH::EM_AARCH64>(uint64_t from,
                                                 uint64_t shift) {
  for (Relocation& relocation : relocations()) {
    if (relocation.address() >= from) {
      // shift_code(relocation.address(), shift, relocation.size() / 8);
      relocation.address(relocation.address() + shift);
    }

    const auto type = static_cast<RELOC_AARCH64>(relocation.type());

    switch (type) {
      case RELOC_AARCH64::R_AARCH64_JUMP_SLOT:
      case RELOC_AARCH64::R_AARCH64_RELATIVE:
      case RELOC_AARCH64::R_AARCH64_GLOB_DAT:
      case RELOC_AARCH64::R_AARCH64_IRELATIVE:
      case RELOC_AARCH64::R_AARCH64_ABS64: {
        LIEF_DEBUG("Patch addend of {}", relocation);
        patch_addend<uint64_t>(relocation, from, shift);
        break;
      }

      case RELOC_AARCH64::R_AARCH64_ABS32: {
        LIEF_DEBUG("Patch addend of {}", relocation);
        patch_addend<uint32_t>(relocation, from, shift);
        break;
      }

      case RELOC_AARCH64::R_AARCH64_ABS16: {
        LIEF_DEBUG("Patch addend of {}", relocation);
        patch_addend<uint16_t>(relocation, from, shift);
        break;
      }

      case RELOC_AARCH64::R_AARCH64_PREL64: {
        LIEF_DEBUG("Patch addend of {}", relocation);
        patch_addend<uint64_t>(relocation, from, shift);
        break;
      }

      case RELOC_AARCH64::R_AARCH64_PREL32: {
        LIEF_DEBUG("Patch addend of {}", relocation);
        patch_addend<uint32_t>(relocation, from, shift);
        break;
      }

      case RELOC_AARCH64::R_AARCH64_PREL16: {
        LIEF_DEBUG("Patch addend of {}", relocation);
        patch_addend<uint16_t>(relocation, from, shift);
        break;
      }

      default: {
        LIEF_DEBUG("Relocation {} is not patched", to_string(type));
      }
    }
  }
}

// ==================
// x86_32 Relocations
// ==================
template <>
void Binary::patch_relocations<ARCH::EM_386>(uint64_t from, uint64_t shift) {
  for (Relocation& relocation : relocations()) {
    if (relocation.address() >= from) {
      // shift_code(relocation.address(), shift, relocation.size() / 8);
      relocation.address(relocation.address() + shift);
    }

    const auto type = static_cast<RELOC_i386>(relocation.type());

    switch (type) {
      case RELOC_i386::R_386_RELATIVE:
      case RELOC_i386::R_386_JUMP_SLOT:
      case RELOC_i386::R_386_IRELATIVE:
      case RELOC_i386::R_386_GLOB_DAT: {
        LIEF_DEBUG("Patch addend of {}", relocation);
        patch_addend<uint32_t>(relocation, from, shift);
        break;
      }

      default: {
        LIEF_WARN("Relocation {} not supported!", to_string(type));
      }
    }
  }
}

// ==================
// x86_64 Relocations
// ==================
template <>
void Binary::patch_relocations<ARCH::EM_X86_64>(uint64_t from, uint64_t shift) {
  for (Relocation& relocation : relocations()) {
    if (relocation.address() >= from) {
      // shift_code(relocation.address(), shift, relocation.size() / 8);
      relocation.address(relocation.address() + shift);
    }

    const auto type = static_cast<RELOC_x86_64>(relocation.type());
    switch (type) {
      case RELOC_x86_64::R_X86_64_RELATIVE:
      case RELOC_x86_64::R_X86_64_IRELATIVE:
      case RELOC_x86_64::R_X86_64_JUMP_SLOT:
      case RELOC_x86_64::R_X86_64_GLOB_DAT:
      case RELOC_x86_64::R_X86_64_64: {
        LIEF_DEBUG("Patch addend of {}", relocation);
        patch_addend<uint64_t>(relocation, from, shift);
        break;
      }

      case RELOC_x86_64::R_X86_64_32: {
        LIEF_DEBUG("Patch addend of {}", relocation);
        patch_addend<uint32_t>(relocation, from, shift);
        break;
      }

      default: {
        LIEF_DEBUG("Relocation {} is not patched", to_string(type));
      }
    }
  }
}

// ==================
// PPC_32 Relocations
// ==================
template <>
void Binary::patch_relocations<ARCH::EM_PPC>(uint64_t from, uint64_t shift) {
  for (Relocation& relocation : relocations()) {
    if (relocation.address() >= from) {
      relocation.address(relocation.address() + shift);
    }

    const auto type = static_cast<RELOC_POWERPC32>(relocation.type());

    switch (type) {
      case RELOC_POWERPC32::R_PPC_RELATIVE: {
        LIEF_DEBUG("Patch addend of {}", relocation);
        patch_addend<uint32_t>(relocation, from, shift);
        break;
      }

      default: {
        LIEF_DEBUG("Relocation {} is not patched", to_string(type));
      }
    }
  }
}

template <class T>
ok_error_t Binary::patch_addend(Relocation& relocation, uint64_t from,
                                uint64_t shift) {
  if (static_cast<uint64_t>(relocation.addend()) >= from) {
    relocation.addend(relocation.addend() + shift);
  }

  const uint64_t address = relocation.address();
  LIEF_DEBUG("Patch addend relocation at address: 0x{:x}", address);
  Segment* segment = segment_from_virtual_address(address);
  if (segment == nullptr) {
    LIEF_ERR("Can't find segment with the virtual address 0x{:x}", address);
  }

  result<uint64_t> maybe_offset = virtual_address_to_offset(address);

  if (is_error(maybe_offset)) {
    return extract_error(maybe_offset);
  }

  const uint64_t relative_offset =
      extract_value(maybe_offset) - segment->file_offset();

  const size_t segment_size = segment->get_content_size();

  if (segment_size == 0) {
    LIEF_WARN("Segment is empty nothing to do");
    return make_error_code(lief_errors::failed_precondition_error);
  }

  if (relative_offset >= segment_size ||
      (relative_offset + sizeof(T)) > segment_size) {
    LIEF_DEBUG("Offset out of bound for relocation: {}", relocation);
    return make_error_code(lief_errors::failed_precondition_error);
  }

  T value = segment->get_content_value<T>(relative_offset);

  if (value >= from) {
    value += shift;
  }

  segment->set_content_value(relative_offset, value);
  return ok();
}

// ========
// ET_EXEC: non-pie executable
//
// For non-pie executable, we move the phdr table at the end of the
// binary and we extend the closest PT_LOAD segment to the end of the
// binary so that it loads the new location of the phdr
//
// The ELF format requires the following relationship between
// segment's VA and segment's offset:
//
// segment_va % pagesize() == segment_offset % pagesize()
//
// It implies that we usually find "cave" between segments
// that could can be large enough to insert our new phdr table.
// To do so, we would just need to extend the PT_LOAD segment associated
// with the caving.
template <>
Segment* Binary::add_segment<E_TYPE::ET_EXEC>(const Segment& segment,
                                              uint64_t base) {
  Header& header = this->header();
  const uint64_t new_phdr_offset = relocate_phdr_table();

  if (new_phdr_offset == 0) {
    LIEF_ERR("We can't relocate the PHDR table for this binary.");
    return nullptr;
  }
  if (phdr_reloc_info_.nb_segments == 0) {
    LIEF_ERR("The segment table is full. We can't add segment");
    return nullptr;
  }

  // const uint64_t phdr_size = type() == ELF_CLASS::ELFCLASS32 ?
  //                                      sizeof(details::ELF32::Elf_Phdr) :
  //                                      sizeof(details::ELF64::Elf_Phdr);

  // Add the segment itself
  // ====================================================================
  // datahandler_->make_hole(new_phdr_offset + phdr_size *
  // header.numberof_segments(), phdr_size);
  header.numberof_segments(header.numberof_segments() + 1);
  span<const uint8_t> content_ref = segment.content();
  std::vector<uint8_t> content{content_ref.data(), std::end(content_ref)};
  auto new_segment = std::make_unique<Segment>(segment);

  uint64_t last_offset_sections = std::accumulate(
      std::begin(sections_), std::end(sections_), 0,
      [](uint64_t offset, const std::unique_ptr<Section>& section) {
        return std::max<uint64_t>(section->file_offset() + section->size(),
                                  offset);
      });

  uint64_t last_offset_segments = std::accumulate(
      std::begin(segments_), std::end(segments_), 0,
      [](uint64_t offset, const std::unique_ptr<Segment>& segment) {
        return std::max<uint64_t>(
            segment->file_offset() + segment->physical_size(), offset);
      });

  uint64_t last_offset =
      std::max<uint64_t>(last_offset_sections, last_offset_segments);

  const auto psize = static_cast<uint64_t>(getpagesize());
  const uint64_t last_offset_aligned = align(last_offset, psize);
  new_segment->file_offset(last_offset_aligned);

  if (segment.virtual_address() == 0) {
    new_segment->virtual_address(base + last_offset_aligned);
  }

  new_segment->physical_address(new_segment->virtual_address());

  uint64_t segmentsize = align(content.size(), psize);
  content.resize(segmentsize, 0);

  new_segment->handler_size_ = content.size();
  new_segment->physical_size(segmentsize);
  new_segment->virtual_size(segmentsize);

  if (new_segment->alignment() == 0) {
    new_segment->alignment(psize);
  }
  new_segment->datahandler_ = datahandler_.get();

  DataHandler::Node new_node{new_segment->file_offset(),
                             new_segment->physical_size(),
                             DataHandler::Node::SEGMENT};
  datahandler_->add(new_node);
  auto alloc = datahandler_->make_hole(last_offset_aligned,
                                       new_segment->physical_size());
  if (!alloc) {
    LIEF_ERR("Allocation failed");
    return nullptr;
  }

  new_segment->content(content);

  if (header.section_headers_offset() <=
      new_segment->file_offset() + new_segment->physical_size()) {
    header.section_headers_offset(header.section_headers_offset() +
                                  new_segment->file_offset() +
                                  new_segment->physical_size());
  }

  const auto it_new_segment_place =
      std::find_if(segments_.rbegin(), segments_.rend(),
                   [&new_segment](const std::unique_ptr<Segment>& s) {
                     return s->type() == new_segment->type();
                   });

  Segment* seg_ptr = new_segment.get();
  if (it_new_segment_place == segments_.rend()) {
    segments_.push_back(std::move(new_segment));
  } else {
    const size_t idx =
        std::distance(std::begin(segments_), it_new_segment_place.base());
    segments_.insert(std::begin(segments_) + idx, std::move(new_segment));
  }
  phdr_reloc_info_.nb_segments--;
  return seg_ptr;
}

// =======================
// ET_DYN (PIE/Libraries)
// =======================
template <>
Segment* Binary::add_segment<E_TYPE::ET_DYN>(const Segment& segment,
                                             uint64_t base) {
  const auto psize = static_cast<uint64_t>(getpagesize());

  /*const uint64_t new_phdr_offset = */ relocate_phdr_table();

  span<const uint8_t> content_ref = segment.content();
  std::vector<uint8_t> content{content_ref.data(), std::end(content_ref)};

  auto new_segment = std::make_unique<Segment>(segment);
  new_segment->datahandler_ = datahandler_.get();

  DataHandler::Node new_node{new_segment->file_offset(),
                             new_segment->physical_size(),
                             DataHandler::Node::SEGMENT};
  datahandler_->add(new_node);

  const uint64_t last_offset_sections = last_offset_section();
  const uint64_t last_offset_segments = last_offset_segment();
  const uint64_t last_offset =
      std::max<uint64_t>(last_offset_sections, last_offset_segments);
  const uint64_t last_offset_aligned = align(last_offset, psize);

  new_segment->file_offset(last_offset_aligned);
  new_segment->virtual_address(new_segment->file_offset() + base);
  new_segment->physical_address(new_segment->virtual_address());

  uint64_t segmentsize = align(content.size(), 0x10);
  // uint64_t segmentsize = content.size();
  new_segment->handler_size_ = content.size();
  new_segment->physical_size(segmentsize);
  new_segment->virtual_size(segmentsize);

  if (new_segment->alignment() == 0) {
    new_segment->alignment(psize);
  }

  // Patch SHDR
  Header& header = this->header();
  const uint64_t new_section_hdr_offset =
      new_segment->file_offset() + new_segment->physical_size();
  header.section_headers_offset(new_section_hdr_offset);

  auto alloc = datahandler_->make_hole(last_offset_aligned,
                                       new_segment->physical_size());

  if (!alloc) {
    LIEF_ERR("Allocation failed");
    return nullptr;
  }

  new_segment->content(content);

  header.numberof_segments(header.numberof_segments() + 1);

  const auto& it_new_segment_place =
      std::find_if(segments_.rbegin(), segments_.rend(),
                   [&new_segment](const std::unique_ptr<Segment>& s) {
                     return s->type() == new_segment->type();
                   });
  Segment* seg_ptr = new_segment.get();
  if (it_new_segment_place == segments_.rend()) {
    segments_.push_back(std::move(new_segment));
  } else {
    const size_t idx =
        std::distance(std::begin(segments_), it_new_segment_place.base());
    segments_.insert(std::begin(segments_) + idx, std::move(new_segment));
  }

  return seg_ptr;
}

// =======================
// Extend PT_LOAD
// =======================
template <>
Segment* Binary::extend_segment<SEGMENT_TYPES::PT_LOAD>(const Segment& segment,
                                                        uint64_t size) {
  const auto it_segment = std::find_if(
      std::begin(segments_), std::end(segments_),
      [&segment](const std::unique_ptr<Segment>& s) { return *s == segment; });

  if (it_segment == std::end(segments_)) {
    LIEF_DEBUG("Unable to find the segment in the current binary");
    return nullptr;
  }

  std::unique_ptr<Segment>& segment_to_extend = *it_segment;

  uint64_t from_offset =
      segment_to_extend->file_offset() + segment_to_extend->physical_size();
  uint64_t from_address =
      segment_to_extend->virtual_address() + segment_to_extend->virtual_size();
  uint64_t shift = size;

  auto alloc = datahandler_->make_hole(
      segment_to_extend->file_offset() + segment_to_extend->physical_size(),
      size);

  if (!alloc) {
    LIEF_ERR("Allocation failed");
    return nullptr;
  }

  shift_sections(from_offset, shift);
  shift_segments(from_offset, shift);

  // Shift
  segment_to_extend->physical_size(segment_to_extend->physical_size() + size);
  segment_to_extend->virtual_size(segment_to_extend->virtual_size() + size);

  span<const uint8_t> content_ref = segment_to_extend->content();
  std::vector<uint8_t> segment_content{content_ref.data(),
                                       std::end(content_ref)};

  segment_content.resize(segment_to_extend->physical_size(), 0);
  segment_to_extend->content(segment_content);

  // Patches
  header().section_headers_offset(header().section_headers_offset() + shift);

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

  return segment_to_extend.get();
}

template <>
Section* Binary::add_section<true>(const Section& section) {
  LIEF_DEBUG("Adding section '{}' as LOADED", section.name());
  // Create a Segment:
  Segment new_segment;
  span<const uint8_t> content_ref = section.content();
  new_segment.content({std::begin(content_ref), std::end(content_ref)});
  new_segment.type(SEGMENT_TYPES::PT_LOAD);

  new_segment.virtual_address(section.virtual_address());
  new_segment.physical_address(section.virtual_address());

  new_segment.physical_size(section.size());
  new_segment.file_offset(section.offset());
  new_segment.alignment(section.alignment());

  new_segment.add(ELF_SEGMENT_FLAGS::PF_R);

  if (section.has(ELF_SECTION_FLAGS::SHF_WRITE)) {
    new_segment.add(ELF_SEGMENT_FLAGS::PF_W);
  }

  if (section.has(ELF_SECTION_FLAGS::SHF_EXECINSTR)) {
    new_segment.add(ELF_SEGMENT_FLAGS::PF_X);
  }

  Segment* segment_added_ptr = add(new_segment);
  if (segment_added_ptr == nullptr) {
    LIEF_DEBUG("Could not add a segment to contain the new section.");
    return nullptr;
  }

  // This is safe because the earlier check passed.
  Segment& segment_added = *segment_added_ptr;
  LIEF_DEBUG("Segment associated: {}@0x{:x}", to_string(segment_added.type()),
             segment_added.virtual_address());

  auto new_section = std::make_unique<Section>(section);
  new_section->datahandler_ = datahandler_.get();

  DataHandler::Node new_node{new_section->file_offset(), new_section->size(),
                             DataHandler::Node::SECTION};
  datahandler_->add(new_node);

  new_section->virtual_address(segment_added.virtual_address());
  new_section->size(segment_added.physical_size());
  new_section->offset(segment_added.file_offset());
  new_section->original_size_ = segment_added.physical_size();

  header().numberof_sections(header().numberof_sections() + 1);

  sections_.push_back(std::move(new_section));
  return sections_.back().get();
}

// Add a non-loaded section
template <>
Section* Binary::add_section<false>(const Section& section) {
  auto new_section = std::make_unique<Section>(section);
  new_section->datahandler_ = datahandler_.get();

  DataHandler::Node new_node{new_section->file_offset(), new_section->size(),
                             DataHandler::Node::SECTION};
  datahandler_->add(new_node);

  const uint64_t last_offset_sections = last_offset_section();
  const uint64_t last_offset_segments = last_offset_segment();
  const uint64_t last_offset =
      std::max<uint64_t>(last_offset_sections, last_offset_segments);

  auto alloc = datahandler_->make_hole(last_offset, section.size());
  if (!alloc) {
    LIEF_ERR("Allocation failed");
    return nullptr;
  }

  new_section->offset(last_offset);
  new_section->size(section.size());

  // Copy original content in the data handler
  span<const uint8_t> content_ref = section.content();
  new_section->content({std::begin(content_ref), std::end(content_ref)});

  header().numberof_sections(header().numberof_sections() + 1);

  Header& header = this->header();
  const uint64_t new_section_hdr_offset =
      new_section->offset() + new_section->size();
  header.section_headers_offset(new_section_hdr_offset);

  sections_.push_back(std::move(new_section));
  return sections_.back().get();
}

template <class ELF_T>
void Binary::fix_got_entries(uint64_t from, uint64_t shift) {
  using ptr_t = typename ELF_T::Elf_Addr;

  DynamicEntry* dt_pltgot = get(DYNAMIC_TAGS::DT_PLTGOT);
  if (dt_pltgot == nullptr) {
    return;
  }
  const uint64_t addr = dt_pltgot->value();
  std::vector<uint8_t> content =
      get_content_from_virtual_address(addr, 3 * sizeof(ptr_t));
  if (content.size() != 3 * sizeof(ptr_t)) {
    LIEF_ERR("Cant't read got entries!");
    return;
  }

  auto got = reinterpret_cast<ptr_t*>(content.data());
  if (got[0] > 0 && got[0] > from) {  // Offset to the dynamic section
    got[0] += shift;
  }

  if (got[1] > 0 && got[1] > from) {  // Prelinked value (unlikely?)
    got[1] += shift;
  }
  patch_address(addr, content);
}

}  // namespace ELF
}  // namespace LIEF
