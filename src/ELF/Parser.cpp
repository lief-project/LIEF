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
#include <memory>
#include <regex>
#include <fstream>
#include <iterator>
#include <iostream>
#include <algorithm>
#include <stdexcept>
#include <functional>

#include "logging.hpp"

#include "LIEF/exception.hpp"
#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/ELF/utils.hpp"
#include "LIEF/ELF/Parser.hpp"
#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/DataHandler/Handler.hpp"
#include "LIEF/ELF/SymbolVersion.hpp"
#include "LIEF/ELF/Segment.hpp"
#include "LIEF/ELF/Section.hpp"
#include "LIEF/ELF/Symbol.hpp"
#include "LIEF/ELF/Note.hpp"
#include "LIEF/ELF/NoteDetails/AndroidNote.hpp"
#include "LIEF/ELF/NoteDetails/Core.hpp"

#include "filesystem/filesystem.h"

#include "Parser.tcc"

namespace LIEF {
namespace ELF {

constexpr uint32_t Parser::NB_MAX_SYMBOLS;
constexpr uint32_t Parser::DELTA_NB_SYMBOLS;
constexpr uint32_t Parser::NB_MAX_BUCKETS;
constexpr uint32_t Parser::NB_MAX_CHAINS;
constexpr uint32_t Parser::NB_MAX_SECTION;
constexpr uint32_t Parser::NB_MAX_SEGMENTS;
constexpr uint32_t Parser::NB_MAX_RELOCATIONS;
constexpr uint32_t Parser::NB_MAX_DYNAMIC_ENTRIES;
constexpr uint32_t Parser::NB_MAX_MASKWORD;
constexpr uint32_t Parser::MAX_NOTE_DESCRIPTION;

constexpr const char AndroidNote::NAME[];


Parser::~Parser() = default;
Parser::Parser()  = default;

Parser::Parser(const std::vector<uint8_t>& data, const std::string& name, DYNSYM_COUNT_METHODS count_mtd, Binary* output) :
  stream_{std::make_unique<VectorStream>(data)},
  type_{ELF_CLASS::ELFCLASSNONE},
  count_mtd_{count_mtd}
{
  if (output != nullptr) {
    binary_ = output;
  } else {
    binary_ = new Binary{};
  }
  init(name);
}

Parser::Parser(const std::string& file, DYNSYM_COUNT_METHODS count_mtd, Binary* output) :
  LIEF::Parser{file},
  type_{ELF_CLASS::ELFCLASSNONE},
  count_mtd_{count_mtd}
{
  if (output != nullptr) {
    binary_ = output;
  } else {
    binary_ = new Binary{};
  }

  stream_ = std::make_unique<VectorStream>(file);
  init(filesystem::path(file).filename());
}

bool Parser::should_swap() const {
  if (!stream_->can_read<details::Elf32_Ehdr>(0)) {
    return false;
  }

  const auto& elf_hdr = stream_->peek<details::Elf32_Ehdr>(0);
  auto endian = static_cast<ELF_DATA>(elf_hdr.e_ident[static_cast<uint8_t>(IDENTITY::EI_DATA)]);

  switch (endian) {
#ifdef __BYTE_ORDER__
#if  defined(__ORDER_LITTLE_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    case ELF_DATA::ELFDATA2MSB:
#elif defined(__ORDER_BIG_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    case ELF_DATA::ELFDATA2LSB:
#endif
      return true;
#endif // __BYTE_ORDER__
    default:
      // we're good (or don't know what to do), consider bytes are in the expected order
      return false;
  }
}

void Parser::init(const std::string& name) {
  LIEF_DEBUG("Parsing binary: {}", name);

  try {
    binary_->original_size_ = binary_size_;
    binary_->name(name);
    binary_->datahandler_ = new DataHandler::Handler{*stream_};

    const auto& elf_hdr = stream_->peek<details::Elf32_Ehdr>(0);
    stream_->set_endian_swap(should_swap());
    uint32_t type = elf_hdr.e_ident[static_cast<size_t>(IDENTITY::EI_CLASS)];

    binary_->type_ = static_cast<ELF_CLASS>(type);
    type_ = static_cast<ELF_CLASS>(type);
    switch (binary_->type_) {
      case ELF_CLASS::ELFCLASS32:
        {
          parse_binary<details::ELF32>();
          break;
        }

      case ELF_CLASS::ELFCLASS64:
        {
          parse_binary<details::ELF64>();
          break;
        }

      case ELF_CLASS::ELFCLASSNONE:
      default:
        //TODO try to guess with e_machine
        throw LIEF::corrupted("e_ident[EI_CLASS] corrupted");
    }
  } catch (const std::exception& e) {
    LIEF_WARN("{}", e.what());
    //delete binary_;
  }
}

std::unique_ptr<Binary> Parser::parse(const std::string& filename, DYNSYM_COUNT_METHODS count_mtd) {
  if (!is_elf(filename)) {
    LIEF_ERR("{} is not an ELF", filename);
    return nullptr;
  }

  Parser parser{filename, count_mtd};
  return std::unique_ptr<Binary>{parser.binary_};
}

std::unique_ptr<Binary> Parser::parse(
    const std::vector<uint8_t>& data,
    const std::string& name,
    DYNSYM_COUNT_METHODS count_mtd) {

  if (!is_elf(data)) {
    LIEF_ERR("{} is not an ELF", name);
    return nullptr;
  }

  Parser parser{data, name, count_mtd};
  return std::unique_ptr<Binary>{parser.binary_};
}


void Parser::parse_symbol_version(uint64_t symbol_version_offset) {
  LIEF_DEBUG("== Parsing symbol version ==");
  LIEF_DEBUG("Symbol version offset: 0x{:x}", symbol_version_offset);

  const auto nb_entries = static_cast<uint32_t>(binary_->dynamic_symbols_.size());

  stream_->setpos(symbol_version_offset);
  for (size_t i = 0; i < nb_entries; ++i) {
    if (!stream_->can_read<uint16_t>()) {
      break;
    }
    binary_->symbol_version_table_.push_back(new SymbolVersion{stream_->read_conv<uint16_t>()});
  }
}


uint64_t Parser::get_dynamic_string_table_from_segments() const {
  //find DYNAMIC segment
  const auto it_segment_dynamic = std::find_if(std::begin(binary_->segments_), std::end(binary_->segments_),
                                               [] (const Segment* segment) {
                                                 return segment->type() == SEGMENT_TYPES::PT_DYNAMIC;
                                               });

  if (it_segment_dynamic == std::end(binary_->segments_)) {
    return 0;
  }

  uint64_t offset = (*it_segment_dynamic)->file_offset();
  uint64_t size   = (*it_segment_dynamic)->physical_size();

  stream_->setpos(offset);

  if (binary_->type_ == ELF_CLASS::ELFCLASS32) {

    size_t nb_entries = size / sizeof(details::Elf32_Dyn);

    for (size_t i = 0; i < nb_entries; ++i) {
      if (!stream_->can_read<details::Elf32_Dyn>()) {
        return 0;
      }
      const auto e = stream_->read_conv<details::Elf32_Dyn>();

      if (static_cast<DYNAMIC_TAGS>(e.d_tag) == DYNAMIC_TAGS::DT_STRTAB) {
        return binary_->virtual_address_to_offset(e.d_un.d_val);
      }
    }

  } else {
    size_t nb_entries = size / sizeof(details::Elf64_Dyn);
    for (size_t i = 0; i < nb_entries; ++i) {

      if (!stream_->can_read<details::Elf64_Dyn>()) {
        return 0;
      }
      const auto e = stream_->read_conv<details::Elf64_Dyn>();

      if (static_cast<DYNAMIC_TAGS>(e.d_tag) == DYNAMIC_TAGS::DT_STRTAB) {
        return binary_->virtual_address_to_offset(e.d_un.d_val);
      }
    }
  }


  return 0;
}

uint64_t Parser::get_dynamic_string_table_from_sections() const {
  // Find Dynamic string section
  auto it_dynamic_string_section = std::find_if(
      std::begin(binary_->sections_),
      std::end(binary_->sections_),
      [] (const Section* section) {
        return section != nullptr && section->name() == ".dynstr" && section->type() == ELF_SECTION_TYPES::SHT_STRTAB;
      });


  uint64_t va_offset = 0;
  if (it_dynamic_string_section != std::end(binary_->sections_)) {
    va_offset = (*it_dynamic_string_section)->file_offset();
  }

  return va_offset;
}

uint64_t Parser::get_dynamic_string_table() const {
  uint64_t offset = get_dynamic_string_table_from_segments();
  if (offset == 0) {
    offset = get_dynamic_string_table_from_sections();
  }
  return offset;
}


void Parser::link_symbol_version() {
  if (binary_->dynamic_symbols_.size() == binary_->symbol_version_table_.size()) {
    for (size_t i = 0; i < binary_->dynamic_symbols_.size(); ++i) {
      binary_->dynamic_symbols_[i]->symbol_version_ = binary_->symbol_version_table_[i];
    }
  }
}

void Parser::parse_symbol_sysv_hash(uint64_t offset) {
  LIEF_DEBUG("== Parse SYSV hash table ==");
  SysvHash sysvhash;

  stream_->setpos(offset);
  std::unique_ptr<uint32_t[]> header = stream_->read_conv_array<uint32_t>(2, /* check */false);

  if (header == nullptr) {
    LIEF_ERR("Can't read SYSV hash table header");
    return;
  }

  const uint32_t nbuckets = std::min<uint32_t>(header[0], Parser::NB_MAX_BUCKETS);
  const uint32_t nchain   = std::min<uint32_t>(header[1], Parser::NB_MAX_CHAINS);

  std::vector<uint32_t> buckets(nbuckets);

  for (size_t i = 0; i < nbuckets; ++i) {
    if (!stream_->can_read<uint32_t>()) {
      break;
    }
    buckets[i] = stream_->read_conv<uint32_t>();
  }

  sysvhash.buckets_ = std::move(buckets);

  std::vector<uint32_t> chains(nchain);

  for (size_t i = 0; i < nchain; ++i) {
    if (!stream_->can_read<uint32_t>()) {
      break;
    }
    chains[i] = stream_->read_conv<uint32_t>();
  }

  sysvhash.chains_ = std::move(chains);
  binary_->sysv_hash_ = sysvhash;
}

void Parser::parse_notes(uint64_t offset, uint64_t size) {
  LIEF_DEBUG("== Parsing note segment ==");

  stream_->setpos(offset);
  uint64_t last_offset = offset + size;

  while(stream_->pos() < last_offset) {
    if (!stream_->can_read<uint32_t>()) {
      break;
    }
    auto namesz = stream_->read_conv<uint32_t>();
    LIEF_DEBUG("Name size: 0x{:x}", namesz);

    if (!stream_->can_read<uint32_t>()) {
      break;
    }
    uint32_t descsz = std::min(stream_->read_conv<uint32_t>(), Parser::MAX_NOTE_DESCRIPTION);

    LIEF_DEBUG("Description size: 0x{:x}", descsz);

    if (!stream_->can_read<uint32_t>()) {
      break;
    }
    auto type = static_cast<NOTE_TYPES>(stream_->read_conv<uint32_t>());
    LIEF_DEBUG("Type: 0x{:x}", static_cast<size_t>(type));

    if (namesz == 0) { // System reserves
      break;
    }

    std::string name = stream_->read_string(namesz);
    LIEF_DEBUG("Name: {}", name);
    stream_->align(sizeof(uint32_t));

    std::vector<uint8_t> description;
    if (descsz > 0) {
      const size_t nb_chunks = (descsz - 1) / sizeof(uint32_t) + 1;
      std::unique_ptr<uint32_t[]> desc_ptr = stream_->read_conv_array<uint32_t>(nb_chunks, /* check */ false);
      if (desc_ptr != nullptr) {
        description = {
          reinterpret_cast<uint8_t *>(desc_ptr.get()),
          reinterpret_cast<uint8_t *>(desc_ptr.get()) + descsz};
      }
      stream_->align(sizeof(uint32_t));
    }
    std::unique_ptr<Note> note;

    if (binary_->header().file_type() == E_TYPE::ET_CORE) {
      note = std::make_unique<Note>(name, static_cast<NOTE_TYPES_CORE>(type), std::move(description), binary_);
    } else {
      note = std::make_unique<Note>(name, type, std::move(description), binary_);
    }

    const auto it_note = std::find_if(
        std::begin(binary_->notes_), std::end(binary_->notes_),
        [&note] (const Note* n) {
          return *n == *note;
        });

    if (it_note == std::end(binary_->notes_)) { // Not already present
      binary_->notes_.push_back(note.release());
    }
  }

}


void Parser::parse_overlay() {
  const uint64_t last_offset = binary_->eof_offset();

  if (last_offset > stream_->size()) {
    return;
  }
  const uint64_t overlay_size = stream_->size() - last_offset;

  if (overlay_size == 0) {
    return;
  }

  LIEF_INFO("Overlay detected at 0x{:x} ({} bytes)", last_offset, overlay_size);

  const auto* overlay = stream_->peek_array<uint8_t>(last_offset, overlay_size, /* check */ false);

  if (overlay == nullptr) {
    LIEF_WARN("Can't read overlay data");
    return;
  }
  binary_->overlay_ = {overlay, overlay + overlay_size};
}



}
}
