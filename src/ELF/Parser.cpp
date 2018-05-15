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
#include <regex>
#include <fstream>
#include <iterator>
#include <iostream>
#include <algorithm>
#include <stdexcept>
#include <functional>

#include "LIEF/logging++.hpp"

#include "LIEF/filesystem/filesystem.h"
#include "LIEF/exception.hpp"

#include "LIEF/ELF/Parser.hpp"
#include "LIEF/ELF/utils.hpp"
#include "LIEF/ELF/AndroidNote.hpp"



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


Parser::~Parser(void) = default;
Parser::Parser(void)  = default;

Parser::Parser(const std::vector<uint8_t>& data, const std::string& name, DYNSYM_COUNT_METHODS count_mtd, Binary* output) :
  stream_{std::unique_ptr<VectorStream>(new VectorStream{data})},
  binary_{nullptr},
  type_{ELF_CLASS::ELFCLASSNONE},
  count_mtd_{count_mtd}
{
  if (output) {
    this->binary_ = output;
  } else {
    this->binary_ = new Binary{};
  }
  this->init(name);
}

Parser::Parser(const std::string& file, DYNSYM_COUNT_METHODS count_mtd, Binary* output) :
  LIEF::Parser{file},
  binary_{nullptr},
  type_{ELF_CLASS::ELFCLASSNONE},
  count_mtd_{count_mtd}
{
  if (output) {
    this->binary_ = output;
  } else {
    this->binary_ = new Binary{};
  }

  this->stream_ = std::unique_ptr<VectorStream>(new VectorStream{file});
  this->init(filesystem::path(file).filename());
}

bool Parser::should_swap(void) const {
  if (not this->stream_->can_read<Elf32_Ehdr>(0)) {
    return false;
  }

  const Elf32_Ehdr& elf_hdr = this->stream_->peek<Elf32_Ehdr>(0);
  ELF_DATA endian = static_cast<ELF_DATA>(elf_hdr.e_ident[static_cast<uint8_t>(IDENTITY::EI_DATA)]);

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
  VLOG(VDEBUG) << "Parsing binary: " << name << std::endl;

  try {
    this->binary_->original_size_ = this->binary_size_;
    this->binary_->name(name);
    this->binary_->datahandler_ = new DataHandler::Handler{this->stream_->content()};

    const Elf32_Ehdr& elf_hdr = this->stream_->peek<Elf32_Ehdr>(0);
    this->stream_->set_endian_swap(this->should_swap());
    uint32_t type = elf_hdr.e_ident[static_cast<size_t>(IDENTITY::EI_CLASS)];

    this->binary_->type_ = static_cast<ELF_CLASS>(type);
    this->type_ = static_cast<ELF_CLASS>(type);
    switch (this->binary_->type_) {
      case ELF_CLASS::ELFCLASS32:
        {
          this->parse_binary<ELF32>();
          break;
        }

      case ELF_CLASS::ELFCLASS64:
        {
          this->parse_binary<ELF64>();
          break;
        }

      case ELF_CLASS::ELFCLASSNONE:
      default:
        //TODO try to guess with e_machine
        throw LIEF::corrupted("e_ident[EI_CLASS] corrupted");
    }
  } catch (const std::exception& e) {
    LOG(WARNING) << e.what();
    //delete this->binary_;
  }
}

Binary* Parser::parse(const std::string& filename, DYNSYM_COUNT_METHODS count_mtd) {
  if (not is_elf(filename)) {
    LOG(ERROR) << filename << " is not an ELF";
    return nullptr;
  }

  Parser parser{filename, count_mtd};
  return parser.binary_;
}

Binary* Parser::parse(
    const std::vector<uint8_t>& data,
    const std::string& name,
    DYNSYM_COUNT_METHODS count_mtd) {

  if (not is_elf(data)) {
    LOG(ERROR) << "'" << name << "' is not an ELF";
    return nullptr;
  }

  Parser parser{data, name, count_mtd};
  return parser.binary_;
}


void Parser::parse_symbol_version(uint64_t symbol_version_offset) {
  VLOG(VDEBUG) << "[+] Parsing symbol version" << std::endl;

  VLOG(VDEBUG) << "Symbol version offset: 0x" << std::hex << symbol_version_offset << std::endl;

  const uint32_t nb_entries = static_cast<uint32_t>(this->binary_->dynamic_symbols_.size());

  this->stream_->setpos(symbol_version_offset);
  for (size_t i = 0; i < nb_entries; ++i) {
    if (not this->stream_->can_read<uint16_t>()) {
      break;
    }
    this->binary_->symbol_version_table_.push_back(new SymbolVersion{this->stream_->read_conv<uint16_t>()});
  }
}


uint64_t Parser::get_dynamic_string_table_from_segments(void) const {
  //find DYNAMIC segment
  auto&& it_segment_dynamic = std::find_if(
      std::begin(this->binary_->segments_),
      std::end(this->binary_->segments_),
      [] (const Segment* segment)
      {
        return segment != nullptr and segment->type() == SEGMENT_TYPES::PT_DYNAMIC;
      });

  if (it_segment_dynamic == std::end(this->binary_->segments_)) {
    return 0;
  }

  uint64_t offset = (*it_segment_dynamic)->file_offset();
  uint64_t size   = (*it_segment_dynamic)->physical_size();

  this->stream_->setpos(offset);

  if (this->binary_->type_ == ELF_CLASS::ELFCLASS32) {

    size_t nb_entries = size / sizeof(Elf32_Dyn);

    for (size_t i = 0; i < nb_entries; ++i) {
      if (not this->stream_->can_read<Elf32_Dyn>()) {
        return 0;
      }
      const Elf32_Dyn e = this->stream_->read_conv<Elf32_Dyn>();

      if (static_cast<DYNAMIC_TAGS>(e.d_tag) == DYNAMIC_TAGS::DT_STRTAB) {
        return this->binary_->virtual_address_to_offset(e.d_un.d_val);
      }
    }

  } else {
    size_t nb_entries = size / sizeof(Elf64_Dyn);
    for (size_t i = 0; i < nb_entries; ++i) {

      if (not this->stream_->can_read<Elf64_Dyn>()) {
        return 0;
      }
      const Elf64_Dyn e = this->stream_->read_conv<Elf64_Dyn>();

      if (static_cast<DYNAMIC_TAGS>(e.d_tag) == DYNAMIC_TAGS::DT_STRTAB) {
        return this->binary_->virtual_address_to_offset(e.d_un.d_val);
      }
    }
  }


  return 0;
}

uint64_t Parser::get_dynamic_string_table_from_sections(void) const {
  // Find Dynamic string section
  auto&& it_dynamic_string_section = std::find_if(
      std::begin(this->binary_->sections_),
      std::end(this->binary_->sections_),
      [] (const Section* section)
      {
        return section != nullptr and section->name() == ".dynstr" and section->type() == ELF_SECTION_TYPES::SHT_STRTAB;
      });


  uint64_t va_offset = 0;
  if (it_dynamic_string_section != std::end(this->binary_->sections_)) {
    va_offset = (*it_dynamic_string_section)->file_offset();
  }

  return va_offset;
}

uint64_t Parser::get_dynamic_string_table(void) const {
  uint64_t offset = this->get_dynamic_string_table_from_segments();
  if (offset == 0) {
    offset = this->get_dynamic_string_table_from_sections();
  }
  CHECK_NE(offset, 0);
  return offset;
}


void Parser::link_symbol_version(void) {
  if (this->binary_->dynamic_symbols_.size() == this->binary_->symbol_version_table_.size()) {
    for (size_t i = 0; i < this->binary_->dynamic_symbols_.size(); ++i) {
      this->binary_->dynamic_symbols_[i]->symbol_version_ = this->binary_->symbol_version_table_[i];
    }
  }
}

void Parser::parse_symbol_sysv_hash(uint64_t offset) {

  VLOG(VDEBUG) << "[+] Parse symbol SYSV hash";
  SysvHash sysvhash;

  this->stream_->setpos(offset);
  std::unique_ptr<uint32_t[]> header = this->stream_->read_conv_array<uint32_t>(2, /* check */false);

  if (header == nullptr) {
    LOG(ERROR) << "Can't read SYSV Hash header";
    return;
  }

  const uint32_t nbuckets = std::min<uint32_t>(header[0], Parser::NB_MAX_BUCKETS);
  const uint32_t nchain   = std::min<uint32_t>(header[1], Parser::NB_MAX_CHAINS);

  std::vector<uint32_t> buckets(nbuckets);

  for (size_t i = 0; i < nbuckets; ++i) {
    if (not this->stream_->can_read<uint32_t>()) {
      break;
    }
    buckets[i] = this->stream_->read_conv<uint32_t>();
  }

  sysvhash.buckets_ = std::move(buckets);

  std::vector<uint32_t> chains(nchain);

  for (size_t i = 0; i < nchain; ++i) {
    if (not this->stream_->can_read<uint32_t>()) {
      break;
    }
    chains[i] = this->stream_->read_conv<uint32_t>();
  }

  sysvhash.chains_ = std::move(chains);

  this->binary_->sysv_hash_ = std::move(sysvhash);

}

void Parser::parse_notes(uint64_t offset, uint64_t size) {
  VLOG(VDEBUG) << "Parsing Note segment";

  this->stream_->setpos(offset);
  uint64_t last_offset = offset + size;

  while(this->stream_->pos() < last_offset) {
    if (not this->stream_->can_read<uint32_t>()) {
      break;
    }
    uint32_t namesz = this->stream_->read_conv<uint32_t>();
    VLOG(VDEBUG) << "Name size: " << std::hex << namesz;


    if (not this->stream_->can_read<uint32_t>()) {
      break;
    }
    uint32_t descsz = std::min(this->stream_->read_conv<uint32_t>(), Parser::MAX_NOTE_DESCRIPTION);

    VLOG(VDEBUG) << "Description size: " << std::hex << descsz;

    if (not this->stream_->can_read<uint32_t>()) {
      break;
    }
    NOTE_TYPES type = static_cast<NOTE_TYPES>(this->stream_->read_conv<uint32_t>());
    VLOG(VDEBUG) << "Type: " << std::hex << static_cast<size_t>(type);

    if (namesz == 0) { // System reserves
      break;
    }

    std::string name = this->stream_->read_string(namesz);
    VLOG(VDEBUG) << "Name: " << name << std::endl;
    this->stream_->align(sizeof(uint32_t));

    std::vector<uint8_t> description;
    if (descsz > 0) {
      const size_t nb_chunks = (descsz - 1) / sizeof(uint32_t) + 1;
      std::unique_ptr<uint32_t[]> desc_ptr = this->stream_->read_conv_array<uint32_t>(nb_chunks, /* check */ false);
      if (desc_ptr != nullptr) {
        description = {
          reinterpret_cast<uint8_t *>(desc_ptr.get()),
          reinterpret_cast<uint8_t *>(desc_ptr.get()) + descsz};
      }
      this->stream_->align(sizeof(uint32_t));
    }
    std::unique_ptr<Note> note;

    if (name == AndroidNote::NAME and type == NOTE_TYPES::NT_GNU_ABI_TAG) {
      note = std::unique_ptr<AndroidNote>{new AndroidNote{name, type, std::move(description)}};
    } else {
      note = std::unique_ptr<Note>{new Note{name, type, std::move(description)}};
    }
    auto&& it_note = std::find_if(
        std::begin(this->binary_->notes_),
        std::end(this->binary_->notes_),
        [&note] (const Note* n) {
          return *n == *note;
        });
    if (it_note == std::end(this->binary_->notes_)) {
      this->binary_->notes_.push_back(note.release());
    }
  }

}



}
}
