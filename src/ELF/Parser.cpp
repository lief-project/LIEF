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
#include "LIEF/BinaryStream/FileStream.hpp"

#include "LIEF/ELF/utils.hpp"
#include "LIEF/ELF/Parser.hpp"
#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/SymbolVersion.hpp"
#include "LIEF/ELF/Segment.hpp"
#include "LIEF/ELF/Section.hpp"
#include "LIEF/ELF/Symbol.hpp"
#include "LIEF/ELF/Note.hpp"
#include "LIEF/ELF/SysvHash.hpp"
#include "LIEF/ELF/NoteDetails/AndroidNote.hpp"
#include "LIEF/ELF/NoteDetails/Core.hpp"

#include "ELF/DataHandler/Handler.hpp"

#include "Parser.tcc"

namespace LIEF {
namespace ELF {

constexpr uint32_t Parser::DELTA_NB_SYMBOLS;
constexpr uint32_t Parser::MAX_NOTE_DESCRIPTION;
constexpr uint32_t Parser::NB_MAX_BUCKETS;
constexpr uint32_t Parser::NB_MAX_CHAINS;
constexpr uint32_t Parser::NB_MAX_DYNAMIC_ENTRIES;
constexpr uint32_t Parser::NB_MAX_MASKWORD;
constexpr uint32_t Parser::NB_MAX_RELOCATIONS;
constexpr uint32_t Parser::NB_MAX_SEGMENTS;
constexpr uint32_t Parser::NB_MAX_SYMBOLS;
constexpr uint32_t Parser::MAX_SEGMENT_SIZE;
constexpr uint32_t Parser::MAX_SECTION_SIZE;

constexpr const char AndroidNote::NAME[];


Parser::~Parser() = default;
Parser::Parser()  = default;

Parser::Parser(const std::vector<uint8_t>& data, DYNSYM_COUNT_METHODS count_mtd) :
  stream_{std::make_unique<VectorStream>(data)},
  binary_{new Binary{}},
  count_mtd_{count_mtd}
{}

Parser::Parser(const std::string& file, DYNSYM_COUNT_METHODS count_mtd) :
  binary_{new Binary{}},
  count_mtd_{count_mtd}
{
  if (auto s = VectorStream::from_file(file)) {
    stream_ = std::make_unique<VectorStream>(std::move(*s));
  }
}

ELF_DATA determine_elf_endianess(ARCH machine) {
  switch (machine) {
    /* Architectures that are known to be big-endian only */
    case ARCH::EM_H8_300:
    case ARCH::EM_SPARC:
    case ARCH::EM_SPARCV9:
    case ARCH::EM_S390:
    case ARCH::EM_68K:
    case ARCH::EM_OPENRISC:
      {
        return ELF_DATA::ELFDATA2MSB;
      }
    /* Architectures that are known to be little-endian only */
    case ARCH::EM_HEXAGON:
    case ARCH::EM_ALPHA:
    case ARCH::EM_ALTERA_NIOS2:
    case ARCH::EM_CRIS:
    case ARCH::EM_386: // x86
    case ARCH::EM_X86_64:
    case ARCH::EM_IA_64:
      {
        return ELF_DATA::ELFDATA2LSB;
      }
    default:
      {
        return ELF_DATA::ELFDATANONE;
      }
  }
}

/*
 * Get the endianess of the current architecture
 */
constexpr ELF_DATA get_endianess() {
  #ifdef __BYTE_ORDER__
    #if defined(__ORDER_LITTLE_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
      return ELF_DATA::ELFDATA2LSB;
    #elif defined(__ORDER_BIG_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
      return ELF_DATA::ELFDATA2MSB;
    #endif
  #endif
  /* If there are no __BYTE_ORDER__ we take the (arbitrary) decision that we are
   * on a little endian architecture.
   */
  return ELF_DATA::ELFDATA2LSB;
}

constexpr ELF_DATA invert_endianess(ELF_DATA endian) {
  if (endian == ELF_DATA::ELFDATA2MSB) {
    return ELF_DATA::ELFDATA2LSB;
  }
  if (endian == ELF_DATA::ELFDATA2LSB) {
    return ELF_DATA::ELFDATA2MSB;
  }
  return ELF_DATA::ELFDATANONE;
}

ELF_DATA determine_elf_endianess(BinaryStream& stream) {
  static const std::set<ARCH> BOTH_ENDIANESS = {
    ARCH::EM_AARCH64, ARCH::EM_ARM,  ARCH::EM_SH,  ARCH::EM_XTENSA,
    ARCH::EM_ARC,     ARCH::EM_MIPS, ARCH::EM_PPC, ARCH::EM_PPC64,
  };
  ELF_DATA from_ei_data   = ELF_DATA::ELFDATANONE;
  /* ELF_DATA from_e_machine = ELF_DATA::ELFDATANONE; */

  // First, check EI_CLASS
  if (auto res = stream.peek<Header::identity_t>()) {
    auto ident = *res;
    uint32_t ei_data = ident[static_cast<size_t>(IDENTITY::EI_DATA)];
    const auto data = static_cast<ELF_DATA>(ei_data);
    if (data == ELF_DATA::ELFDATA2LSB || data == ELF_DATA::ELFDATA2MSB) {
      from_ei_data = data;
    }
  }

  // Try to determine the size based on Elf_Ehdr.e_machine
  //
  // typedef struct {
  //     unsigned char e_ident[EI_NIDENT]; | +0x00
  //     uint16_t      e_type;             | +0x10
  //     uint16_t      e_machine;          | +0x12 <------ THIS
  //     uint32_t      e_version;          |
  //     ....
  // } ElfN_Ehdr;
  constexpr size_t e_machine_off = offsetof(details::Elf32_Ehdr, e_machine);
  {
    // Read Machine type with both endianess
    ARCH machine      = ARCH::EM_NONE; // e_machine value without endian swap enabled
    ARCH machine_swap = ARCH::EM_NONE; // e_machine value with endian swap enabled
    const bool is_swap = stream.should_swap();
    stream.set_endian_swap(false);
    if (auto res = stream.peek_conv<uint16_t>(e_machine_off)) {
      machine = static_cast<ARCH>(*res);
    }
    stream.set_endian_swap(true);
    if (auto res = stream.peek_conv<uint16_t>(e_machine_off)) {
      machine_swap = static_cast<ARCH>(*res);
    }
    stream.set_endian_swap(is_swap);

    LIEF_DEBUG("Machine     '{}'", to_string(machine));
    LIEF_DEBUG("Machine Swap'{}'", to_string(machine_swap));

    const ELF_DATA endian      = determine_elf_endianess(machine);
    const ELF_DATA endian_swap = determine_elf_endianess(machine_swap);

    if (endian != ELF_DATA::ELFDATANONE) {
      return endian;
    }

    if (endian_swap != ELF_DATA::ELFDATANONE) {
      return endian_swap;
    }

    if (BOTH_ENDIANESS.find(machine) != std::end(BOTH_ENDIANESS)) {
      return get_endianess();
    }

    if (BOTH_ENDIANESS.find(machine_swap) != std::end(BOTH_ENDIANESS)) {
      return invert_endianess(get_endianess());
    }
  }
  return from_ei_data;
}

bool Parser::should_swap() const {
  const ELF_DATA binary_endian  = determine_elf_endianess(*stream_);
  const ELF_DATA current_endian = get_endianess();
  LIEF_DEBUG("LIEF Endianness:   '{}'", to_string(current_endian));
  LIEF_DEBUG("Binary Endianness: '{}'", to_string(binary_endian));
  if (binary_endian  != ELF_DATA::ELFDATANONE &&
      current_endian != ELF_DATA::ELFDATANONE)
  {
    return binary_endian != current_endian;
  }
  return false;
}



ELF_CLASS determine_elf_class(BinaryStream& stream) {
  ELF_CLASS from_ei_class  = ELF_CLASS::ELFCLASSNONE;
  ELF_CLASS from_e_machine = ELF_CLASS::ELFCLASSNONE;

  // First, check EI_CLASS
  if (auto res = stream.peek<Header::identity_t>()) {
    auto ident = *res;
    uint32_t ei_class = ident[static_cast<size_t>(IDENTITY::EI_CLASS)];
    const auto typed = static_cast<ELF_CLASS>(ei_class);
    if (typed == ELF_CLASS::ELFCLASS32 || typed == ELF_CLASS::ELFCLASS64) {
      from_ei_class = typed;
    }
  }

  // Try to determine the size based on Elf_Ehdr.e_machine
  //
  // typedef struct {
  //     unsigned char e_ident[EI_NIDENT]; | +0x00
  //     uint16_t      e_type;             | +0x10
  //     uint16_t      e_machine;          | +0x12 <------ THIS
  //     uint32_t      e_version;          |
  //     ....
  // } ElfN_Ehdr;
  constexpr size_t e_machine_off = offsetof(details::Elf32_Ehdr, e_machine);
  if (auto res = stream.peek_conv<uint16_t>(e_machine_off)) {
    const auto machine = static_cast<ARCH>(*res);
    switch (machine) {
      case ARCH::EM_AARCH64:
      case ARCH::EM_X86_64:
      case ARCH::EM_PPC64:
      case ARCH::EM_SPARCV9:
      case ARCH::EM_IA_64:
        {
          from_e_machine = ELF_CLASS::ELFCLASS64;
          break;
        }
      case ARCH::EM_386:
      case ARCH::EM_ARM:
      case ARCH::EM_PPC:
        {
          from_e_machine = ELF_CLASS::ELFCLASS32;
          break;
        }
      default:
        {
          from_e_machine = ELF_CLASS::ELFCLASSNONE;
          break;
        }
    }
  }
  if (from_e_machine != ELF_CLASS::ELFCLASSNONE &&
      from_ei_class != ELF_CLASS::ELFCLASSNONE)
  {
    if (from_e_machine == from_ei_class) {
      return from_ei_class;
    }

    LIEF_WARN("ELF class from machine type ('{}') does not match ELF class from "
              "e_ident ('{}'). The binary has been likely modified.",
              to_string(from_e_machine), to_string(from_ei_class));
    // Make the priority on Elf_Ehdr.e_machine as it is
    // this value that is used by the kernel.
    return from_e_machine;
  }
  if (from_e_machine != ELF_CLASS::ELFCLASSNONE) {
    return from_e_machine;
  }
  return from_ei_class;
}


ok_error_t Parser::init(const std::string& name) {
  LIEF_DEBUG("Parsing binary: {}", name);

  if (stream_ == nullptr) {
    LIEF_ERR("Stream not properly initialized");
    return make_error_code(lief_errors::parsing_error);
  }

  binary_->original_size_ = binary_size_;
  binary_->name(name);
  auto res = DataHandler::Handler::from_stream(stream_);
  if (!res) {
    LIEF_ERR("The provided stream is not supported by the ELF DataHandler");
    return make_error_code(lief_errors::not_supported);
  }

  binary_->datahandler_ = std::move(*res);

  auto res_ident = stream_->peek<Header::identity_t>();
  if (!res_ident) {
    LIEF_ERR("Can't read ELF identity. Nothing to parse");
    return res_ident.error();
  }
  stream_->set_endian_swap(should_swap());

  binary_->type_ = determine_elf_class(*stream_);
  type_ = binary_->type_;

  switch (type_) {
    case ELF_CLASS::ELFCLASS32: return parse_binary<details::ELF32>();
    case ELF_CLASS::ELFCLASS64: return parse_binary<details::ELF64>();
    case ELF_CLASS::ELFCLASSNONE:
    default:
      {
        LIEF_ERR("Can't determine the ELF class ({})", static_cast<size_t>(type_));
        return make_error_code(lief_errors::corrupted);
      }
  }

  return ok();
}

std::unique_ptr<Binary> Parser::parse(const std::string& filename, DYNSYM_COUNT_METHODS count_mtd) {
  if (!is_elf(filename)) {
    return nullptr;
  }

  Parser parser{filename, count_mtd};
  parser.init(filename);
  return std::move(parser.binary_);
}

std::unique_ptr<Binary> Parser::parse(const std::vector<uint8_t>& data,
                                      const std::string& name, DYNSYM_COUNT_METHODS count_mtd) {
  if (!is_elf(data)) {
    return nullptr;
  }

  Parser parser{data, count_mtd};
  parser.init(name);
  return std::move(parser.binary_);
}


ok_error_t Parser::parse_symbol_version(uint64_t symbol_version_offset) {
  LIEF_DEBUG("== Parsing symbol version ==");
  LIEF_DEBUG("Symbol version offset: 0x{:x}", symbol_version_offset);

  const auto nb_entries = static_cast<uint32_t>(binary_->dynamic_symbols_.size());

  stream_->setpos(symbol_version_offset);
  for (size_t i = 0; i < nb_entries; ++i) {
    auto val = stream_->read_conv<uint16_t>();
    if (!val) {
      break;
    }
    binary_->symbol_version_table_.emplace_back(std::make_unique<SymbolVersion>(*val));
  }
  return ok();
}


result<uint64_t> Parser::get_dynamic_string_table_from_segments() const {
  Segment* dyn_segment = binary_->get(SEGMENT_TYPES::PT_DYNAMIC);
  if (dyn_segment == nullptr) {
    return 0;
  }

  const uint64_t offset = dyn_segment->file_offset();
  const uint64_t size   = dyn_segment->physical_size();

  stream_->setpos(offset);

  if (binary_->type_ == ELF_CLASS::ELFCLASS32) {
    size_t nb_entries = size / sizeof(details::Elf32_Dyn);

    for (size_t i = 0; i < nb_entries; ++i) {
      auto res = stream_->read_conv<details::Elf32_Dyn>();
      if (!res) {
        LIEF_ERR("Can't read dynamic entry #{}", i);
        return 0;
      }
      auto dt = *res;

      if (static_cast<DYNAMIC_TAGS>(dt.d_tag) == DYNAMIC_TAGS::DT_STRTAB) {
        return binary_->virtual_address_to_offset(dt.d_un.d_val);
      }
    }

  } else {
    size_t nb_entries = size / sizeof(details::Elf64_Dyn);
    for (size_t i = 0; i < nb_entries; ++i) {
      auto res = stream_->read_conv<details::Elf64_Dyn>();
      if (!res) {
        LIEF_ERR("Can't read dynamic entry #{}", i);
        return 0;
      }
      const auto dt = *res;

      if (static_cast<DYNAMIC_TAGS>(dt.d_tag) == DYNAMIC_TAGS::DT_STRTAB) {
        return binary_->virtual_address_to_offset(dt.d_un.d_val);
      }
    }
  }
  return 0;
}

uint64_t Parser::get_dynamic_string_table_from_sections() const {
  // Find Dynamic string section
  auto it_dynamic_string_section = std::find_if(
      std::begin(binary_->sections_), std::end(binary_->sections_),
      [] (const std::unique_ptr<Section>& section) {
        return section->name() == ".dynstr" &&
               section->type() == ELF_SECTION_TYPES::SHT_STRTAB;
      });


  if (it_dynamic_string_section == std::end(binary_->sections_)) {
    return 0;
  }
  return (*it_dynamic_string_section)->file_offset();
}

uint64_t Parser::get_dynamic_string_table() const {
  if (auto res = get_dynamic_string_table_from_segments()) {
    return *res;
  }
  return get_dynamic_string_table_from_sections();
}


void Parser::link_symbol_version() {
  if (binary_->dynamic_symbols_.size() == binary_->symbol_version_table_.size()) {
    for (size_t i = 0; i < binary_->dynamic_symbols_.size(); ++i) {
      binary_->dynamic_symbols_[i]->symbol_version_ = binary_->symbol_version_table_[i].get();
    }
  }
}

ok_error_t Parser::parse_symbol_sysv_hash(uint64_t offset) {
  LIEF_DEBUG("== Parse SYSV hash table ==");
  auto sysvhash = std::make_unique<SysvHash>();

  stream_->setpos(offset);

  auto res_nbucket = stream_->read_conv<uint32_t>();
  if (!res_nbucket) {
    LIEF_ERR("Can't read the number of buckets");
    return make_error_code(lief_errors::read_error);
  }

  auto res_nchains = stream_->read_conv<uint32_t>();
  if (!res_nchains) {
    LIEF_ERR("Can't read the number of chains");
    return make_error_code(lief_errors::read_error);
  }

  const auto nbuckets = std::min<uint32_t>(*res_nbucket, Parser::NB_MAX_BUCKETS);
  const auto nchain   = std::min<uint32_t>(*res_nchains, Parser::NB_MAX_CHAINS);

  sysvhash->buckets_.reserve(nbuckets);

  for (size_t i = 0; i < nbuckets; ++i) {
    if (auto bucket = stream_->read_conv<uint32_t>()) {
      sysvhash->buckets_.push_back(*bucket);
    } else {
      LIEF_ERR("Can't read bucket #{}", i);
      break;
    }
  }

  sysvhash->chains_.reserve(nchain);
  for (size_t i = 0; i < nchain; ++i) {
    if (auto chain = stream_->read_conv<uint32_t>()) {
      sysvhash->chains_.push_back(*chain);
    } else {
      LIEF_ERR("Can't read chain #{}", i);
      break;
    }
  }

  binary_->sysv_hash_ = std::move(sysvhash);
  binary_->sizing_info_->hash = stream_->pos() - offset;
  return ok();
}

ok_error_t Parser::parse_notes(uint64_t offset, uint64_t size) {
  LIEF_DEBUG("== Parsing note segment ==");

  stream_->setpos(offset);
  uint64_t last_offset = offset + size;

  while(stream_->pos() < last_offset) {
    auto res_namesz = stream_->read_conv<uint32_t>();
    if (!res_namesz) {
      break;
    }

    const auto namesz = *res_namesz;
    LIEF_DEBUG("Name size: 0x{:x}", namesz);

    auto res_descz = stream_->read_conv<uint32_t>();
    if (!res_descz) {
      break;
    }

    uint32_t descsz = std::min(*res_descz, Parser::MAX_NOTE_DESCRIPTION);
    LIEF_DEBUG("Description size: 0x{:x}", descsz);

    auto res_type = stream_->read_conv<uint32_t>();
    if (!res_type) {
      break;
    }

    auto type = static_cast<NOTE_TYPES>(*res_type);
    LIEF_DEBUG("Type: 0x{:x}", static_cast<size_t>(type));

    if (namesz == 0) { // System reserves
      break;
    }

    auto res_name = stream_->read_string(namesz);
    if (!res_name) {
      LIEF_ERR("Can't read note name");
      break;
    }
    std::string name = std::move(*res_name);

    LIEF_DEBUG("Name: {}", name);
    stream_->align(sizeof(uint32_t));

    std::vector<uint32_t> description;
    if (descsz > 0) {
      const size_t nb_chunks = (descsz - 1) / sizeof(uint32_t) + 1;
      description.reserve(nb_chunks);
      for (size_t i = 0; i < nb_chunks; ++i) {
        if (const auto chunk = stream_->read_conv<uint32_t>()) {
          description.push_back(*chunk);
        } else {
          break;
        }
      }
      stream_->align(sizeof(uint32_t));
    }
    std::unique_ptr<Note> note;
    std::vector<uint8_t> desc_bytes;
    if (!description.empty()) {
      desc_bytes = {
          reinterpret_cast<const uint8_t*>(description.data()),
          reinterpret_cast<const uint8_t*>(description.data()) + description.size() * sizeof(uint32_t)
      };
    }

    if (binary_->header().file_type() == E_TYPE::ET_CORE) {
      note = std::make_unique<Note>(name, static_cast<NOTE_TYPES_CORE>(type),
                                    std::move(desc_bytes), binary_.get());
    } else {
      note = std::make_unique<Note>(name, type, std::move(desc_bytes), binary_.get());
    }

    const auto it_note = std::find_if(
        std::begin(binary_->notes_), std::end(binary_->notes_),
        [&note] (const std::unique_ptr<Note>& n) { return *n == *note; });

    if (it_note == std::end(binary_->notes_)) { // Not already present
      binary_->notes_.push_back(std::move(note));
    }
  }
  return ok();
}


ok_error_t Parser::parse_overlay() {
  const uint64_t last_offset = binary_->eof_offset();

  if (last_offset > stream_->size()) {
    return ok();
  }
  const uint64_t overlay_size = stream_->size() - last_offset;

  if (overlay_size == 0) {
    return ok();
  }

  LIEF_INFO("Overlay detected at 0x{:x} ({} bytes)", last_offset, overlay_size);

  if (!stream_->peek_data(binary_->overlay_, last_offset, overlay_size)) {
    LIEF_WARN("Can't read overlay data");
    return make_error_code(lief_errors::read_error);
  }
  return ok();
}

bool Parser::check_section_in_segment(const Section& section, const Segment& segment) {
  if (section.virtual_address() > 0) {
    const uint64_t seg_vend = segment.virtual_address() + segment.virtual_size();
    return segment.virtual_address() <= section.virtual_address() &&
           section.virtual_address() + section.size() <= seg_vend;
  }

  if (section.file_offset() > 0) {
    const uint64_t seg_end = segment.file_offset() + segment.physical_size();
    return segment.file_offset() <= section.file_offset() &&
           section.file_offset() + section.size() <= seg_end;
  }
  return false;
}




}
}
