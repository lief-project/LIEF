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
#include "LIEF/logging++.hpp"
#include "LIEF/ELF/enums.hpp"
namespace LIEF {
namespace ELF {

// ============
// ET_LIEF_DYN
// ============
template<>
Segment& Binary::add_segment<E_TYPE::ET_LIEF_DYN>(const Segment& segment, uint64_t base) {
  Header& header = this->header();

  uint64_t last_offset_sections = std::accumulate(
      std::begin(this->sections_),
      std::end(this->sections_), 0,
      [] (uint64_t offset, const Section* section) {
        return std::max<uint64_t>(section->file_offset() + section->size(), offset);
      });

  uint64_t last_offset_segments = std::accumulate(
      std::begin(this->segments_),
      std::end(this->segments_), 0,
      [] (uint64_t offset, const Segment* segment) {
        return std::max<uint64_t>(segment->file_offset() + segment->physical_size(), offset);
      });

  uint64_t last_offset     = std::max<uint64_t>(last_offset_sections, last_offset_segments);
  uint64_t new_phdr_offset = last_offset;

  header.numberof_segments(header.numberof_segments() + 1);

  uint64_t phdr_size = 0;
  if (this->type() == ELF_CLASS::ELFCLASS32) {
    phdr_size = sizeof(ELF32::Elf_Phdr);
  }

  if (this->type() == ELF_CLASS::ELFCLASS64) {
    phdr_size = sizeof(ELF64::Elf_Phdr);
  }


  std::vector<uint8_t> content = segment.content();
  Segment* new_segment = new Segment{segment};
  new_segment->datahandler_ = this->datahandler_;

  DataHandler::Node new_node{
          new_segment->file_offset(),
          new_segment->physical_size(),
          DataHandler::Node::SEGMENT};
  this->datahandler_->add(new_node);

  const uint64_t psize = static_cast<uint64_t>(getpagesize());
  const uint64_t last_offset_aligned = align(last_offset, psize);

  new_segment->file_offset(last_offset_aligned);
  if (segment.virtual_address() == 0) {
    new_segment->virtual_address(base + last_offset_aligned);
  }

  new_segment->physical_address(new_segment->virtual_address());

  uint64_t segmentsize = align(content.size(), psize);
  content.resize(segmentsize, 0);

  new_segment->physical_size(segmentsize);
  new_segment->virtual_size(segmentsize);

  if (new_segment->alignment() == 0) {
    new_segment->alignment(psize);
  }

  this->datahandler_->make_hole(last_offset_aligned, new_segment->physical_size());
  new_segment->content(content);

  //if (header.section_headers_offset() <= new_segment->file_offset() + new_segment->physical_size()) {
  //
  //header.section_headers_offset(header.section_headers_offset() + new_phdr_offset + phdr_size * header.numberof_segments());
  header.section_headers_offset(header.section_headers_offset() + new_segment->file_offset() + new_segment->physical_size() + phdr_size);

  //}

  //if (header.program_headers_offset() <= new_segment->file_offset() + new_segment->physical_size()) {
  header.program_headers_offset(header.program_headers_offset() + new_segment->file_offset() + new_segment->physical_size());
  //}

  auto&& it_new_segment_place = std::find_if(
      this->segments_.rbegin(),
      this->segments_.rend(),
      [&new_segment] (const Segment* s) {
        return s->type() == new_segment->type();
      });

  if (it_new_segment_place == this->segments_.rend()) {
    this->segments_.push_back(new_segment);
  } else {
    const size_t idx = std::distance(std::begin(this->segments_), it_new_segment_place.base());
    this->segments_.insert(std::begin(this->segments_) + idx, new_segment);
  }

  return *new_segment;

}


template<class T>
std::unique_ptr<Binary> Binary::create_lief_dyn_impl(ARCH arch, ELF_CLASS clazz) {
  using Elf_Phdr = typename T::Elf_Phdr;
  using Elf_Ehdr = typename T::Elf_Ehdr;
  using Elf_Shdr = typename T::Elf_Shdr;

  std::unique_ptr<Binary> new_binary{new Binary{}};
  new_binary->type_ = clazz;

  // Set header
  new_binary->header_.file_type(E_TYPE::ET_LIEF_DYN);
  new_binary->header_.machine_type(arch);
  new_binary->header_.object_file_version(VERSION::EV_CURRENT);
  new_binary->header_.entrypoint(0);


  new_binary->header_.processor_flag(0);

  new_binary->header_.header_size(sizeof(Elf_Ehdr));
  new_binary->header_.program_header_size(sizeof(Elf_Phdr));
  new_binary->header_.section_header_size(sizeof(Elf_Shdr));

  std::string ident = "\x7F";
  new_binary->header_.identity(ident + "ELF");
  new_binary->header_.identity_class(clazz);
  new_binary->header_.identity_data(ELF_DATA::ELFDATA2LSB);
  new_binary->header_.identity_version(VERSION::EV_CURRENT);
  new_binary->header_.identity_os_abi(OS_ABI::ELFOSABI_SYSTEMV);


  new_binary->datahandler_ = new DataHandler::Handler{std::vector<uint8_t>{}};

  size_t cursor = sizeof(Elf_Ehdr);
  // Add new null entry section

  Section* null = new Section{"", ELF_SECTION_TYPES::SHT_NULL};
  null->datahandler_ = new_binary->datahandler_;
  new_binary->datahandler_->add({null->file_offset(), null->size(), DataHandler::Node::SECTION});

  new_binary->sections_.push_back(null);

  Section* shstrtab = new Section{".shstrtab", ELF_SECTION_TYPES::SHT_STRTAB};
  shstrtab->offset(cursor);

  shstrtab->datahandler_ = new_binary->datahandler_;
  new_binary->datahandler_->add({shstrtab->file_offset(), 0, DataHandler::Node::SECTION});
  shstrtab->size(100);
  cursor += shstrtab->size();
  new_binary->sections_.push_back(shstrtab);
  new_binary->datahandler_->make_hole(shstrtab->file_offset(), shstrtab->size());

  new_binary->header_.program_headers_offset(cursor);
  cursor += 1;

  new_binary->header_.section_headers_offset(cursor);
  new_binary->header_.section_name_table_idx(new_binary->sections_.size() - 1);

  const size_t shdr_sizes = (new_binary->sections_.size() + 1) * sizeof(Elf_Shdr);
  cursor += shdr_sizes;

  new_binary->header().numberof_sections(new_binary->sections_.size());
  new_binary->header().numberof_segments(new_binary->segments_.size());
  return new_binary;
}

}
}
