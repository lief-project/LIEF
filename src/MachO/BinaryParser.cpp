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
#include <fstream>
#include <iterator>
#include <iostream>
#include <algorithm>
#include <regex>
#include <stdexcept>
#include <functional>


#include "LIEF/BinaryStream/VectorStream.hpp"
#include "LIEF/filesystem/filesystem.h"
#include "LIEF/exception.hpp"

#include "LIEF/MachO/BinaryParser.hpp"
#include "BinaryParser.tcc"

#include "LIEF/MachO/utils.hpp"
#include "LIEF/MachO/Header.hpp"
#include "LIEF/MachO/LoadCommand.hpp"
#include "LIEF/MachO/SegmentCommand.hpp"
#include "LIEF/MachO/Section.hpp"
#include "LIEF/MachO/UUIDCommand.hpp"
#include "LIEF/MachO/SymbolCommand.hpp"
#include "LIEF/MachO/Symbol.hpp"
#include "LIEF/MachO/EnumToString.hpp"

namespace LIEF {
namespace MachO {

BinaryParser::BinaryParser(void) = default;
BinaryParser::~BinaryParser(void) = default;

BinaryParser::BinaryParser(const std::vector<uint8_t>& data, uint64_t fat_offset, const ParserConfig& conf) :
  stream_{new VectorStream{data}},
  binary_{new Binary{}},
  config_{conf}
{
  this->binary_->fat_offset_ = fat_offset;
  this->init();
}


BinaryParser::BinaryParser(std::unique_ptr<VectorStream>&& stream, uint64_t fat_offset, const ParserConfig& conf) :
  stream_{std::move(stream)},
  binary_{new Binary{}},
  config_{conf}
{
  this->binary_->fat_offset_ = fat_offset;
  this->init();
}

BinaryParser::BinaryParser(const std::string& file, const ParserConfig& conf) :
  LIEF::Parser{file},
  config_{conf}
{

  if (not is_macho(file)) {
    throw bad_file("'" + file + "' is not a MachO binary");
  }


  if (not is_fat(file)) {
    throw bad_file("'" + file + "' is a FAT MachO, this parser takes fit binary");
  }

  this->stream_ = std::unique_ptr<VectorStream>(new VectorStream{file});

  this->binary_ = new Binary{};
  this->binary_->name_ = filesystem::path(file).filename();
  this->binary_->fat_offset_ = 0;

  this->init();
}

void BinaryParser::init(void) {
  VLOG(VDEBUG) << "Parsing MachO" << std::endl;
  try {
    MACHO_TYPES type = static_cast<MACHO_TYPES>(this->stream_->peek<uint32_t>(0));

    if (type == MACHO_TYPES::MH_MAGIC_64 or
        type == MACHO_TYPES::MH_CIGAM_64 )
    {
      this->is64_ = true;
    }
    else
    {
      this->is64_ = false;
    }

    this->binary_->is64_ = this->is64_;
    this->type_          = type;

    if (this->is64_) {
      this->parse<MachO64>();
    } else {
      this->parse<MachO32>();
    }
  } catch (const std::exception& e) {
    VLOG(VDEBUG) << e.what();
  }

}


void BinaryParser::parse_export_trie(uint64_t start, uint64_t end, const std::string& prefix) {
  if (this->stream_->pos() >= end) {
    return;
  }

  if (start > this->stream_->pos()) {
    return;
  }

  const uint8_t terminal_size = this->stream_->read<uint8_t>();
  uint64_t children_offset = this->stream_->pos() + terminal_size;

  if (terminal_size != 0) {
    uint64_t offset = this->stream_->pos() - start;

    uint64_t flags   = this->stream_->read_uleb128();
    uint64_t address = this->stream_->read_uleb128();

    const std::string& symbol_name = prefix;
    std::unique_ptr<ExportInfo> export_info{new ExportInfo{address, flags, offset}};
    if (this->binary_->has_symbol(symbol_name)) {
      Symbol& symbol = this->binary_->get_symbol(symbol_name);
      export_info->symbol_ = &symbol;
      symbol.export_info_ = export_info.get();
    } else { // Register it into the symbol table
      std::unique_ptr<Symbol> symbol{new Symbol{}};
      symbol->origin_            = SYMBOL_ORIGINS::SYM_ORIGIN_DYLD_EXPORT;
      symbol->value_             = export_info->address();
      symbol->type_              = 0;
      symbol->numberof_sections_ = 0;
      symbol->description_       = 0;
      symbol->name(symbol_name);

      // Weak bind of the pointer
      symbol->export_info_       = export_info.get();
      export_info->symbol_       = symbol.get();
      this->binary_->symbols_.push_back(symbol.release());
    }
    this->binary_->dyld_info().export_info_.push_back(export_info.release());

  }
  this->stream_->setpos(children_offset);
	const uint8_t nb_children = this->stream_->read<uint8_t>();
  for (size_t i = 0; i < nb_children; ++i) {
    std::string suffix = this->stream_->read_string();
    std::string name   = prefix + suffix;

    uint32_t child_node_offet = static_cast<uint32_t>(this->stream_->read_uleb128());

    if (child_node_offet == 0) {
      break;
    }
    size_t current_pos = this->stream_->pos();
    this->stream_->setpos(start + child_node_offet);
    this->parse_export_trie(start, end, name);
    this->stream_->setpos(current_pos);
  }

}

void BinaryParser::parse_dyldinfo_export(void) {

  DyldInfo& dyldinfo = this->binary_->dyld_info();

  uint32_t offset = std::get<0>(dyldinfo.export_info());
  uint32_t size   = std::get<1>(dyldinfo.export_info());

  if (offset == 0 or size == 0) {
    return;
  }

  uint64_t end_offset = offset + size;

  try {
    const uint8_t* raw_trie = this->stream_->peek_array<uint8_t>(offset, size, /* check */ false);
    if (raw_trie != nullptr) {
      dyldinfo.export_trie({raw_trie, raw_trie + size});
    }
  } catch (const exception& e) {
    LOG(WARNING) << e.what();
  }

  this->stream_->setpos(offset);
  this->parse_export_trie(offset, end_offset, "");
}

Binary* BinaryParser::get_binary(void) {
  return this->binary_;
}

} // namespace MachO
} // namespace LIEF
