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
    MACHO_TYPES type = static_cast<MACHO_TYPES>(
        *reinterpret_cast<const uint32_t*>(this->stream_->read(0, sizeof(uint32_t))));

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


void BinaryParser::parse_export_trie(uint64_t start, uint64_t current_offset, uint64_t end, const std::string& prefix) {
  std::pair<uint64_t, uint64_t> value_delta = {0, 0};
  if (current_offset >= end) {
    return;
  }

  if (start > current_offset) {
    return;
  }

  const uint8_t terminal_size = this->stream_->read_integer<uint8_t>(current_offset);
  current_offset += sizeof(uint8_t);

  uint64_t children_offset = current_offset + terminal_size;

  if (terminal_size != 0) {
    uint64_t offset = current_offset - start;

    value_delta     = this->stream_->read_uleb128(current_offset);
    uint64_t flags  = std::get<0>(value_delta);
    current_offset += std::get<1>(value_delta);

    value_delta       = this->stream_->read_uleb128(current_offset);
    uint64_t address  = std::get<0>(value_delta);
    current_offset   += std::get<1>(value_delta);

    const std::string& symbol_name = prefix;
    std::unique_ptr<ExportInfo> export_info{new ExportInfo{address, flags, offset}};
    if (this->binary_->has_symbol(symbol_name)) {
      Symbol& symbol = this->binary_->get_symbol(symbol_name);
      export_info->symbol_ = &symbol;
      symbol.export_info_ = export_info.get();
      //if (symbol.is_external()) {
      //  //LOG(WARNING) << "FOOOOO " << symbol_name;
      //  //TODO
      //}
    } else {
      LOG(WARNING) << "'" << symbol_name << "' is not registred";
    }
    this->binary_->dyld_info().export_info_.push_back(export_info.release());

  }

	const uint8_t nb_children = this->stream_->read_integer<uint8_t>(children_offset);
  children_offset += sizeof(uint8_t);
  for (size_t i = 0; i < nb_children; ++i) {
    std::string suffix = this->stream_->get_string(children_offset);
    std::string name   = prefix + suffix;

    children_offset += suffix.size() + 1;

    value_delta                = this->stream_->read_uleb128(children_offset);
    uint32_t child_node_offet  = static_cast<uint32_t>(std::get<0>(value_delta));
    children_offset           += std::get<1>(value_delta);
    if (start + child_node_offet == start) {
      break;
    }
    this->parse_export_trie(start, start + child_node_offet, end, name);
  }

}

void BinaryParser::parse_dyldinfo_export(void) {

  DyldInfo& dyldinfo = this->binary_->dyld_info();

  uint32_t offset = std::get<0>(dyldinfo.export_info());
  uint32_t size   = std::get<1>(dyldinfo.export_info());

  if (offset == 0 or size == 0) {
    return;
  }

  uint64_t current_offset = offset;
  uint64_t end_offset     = offset + size;

  try {
    const uint8_t* raw_trie = reinterpret_cast<const uint8_t*>(this->stream_->read(offset, size));
    dyldinfo.export_trie({raw_trie, raw_trie + size});
  } catch (const exception& e) {
    LOG(WARNING) << e.what();
  }

  this->parse_export_trie(offset, current_offset, end_offset, "");
}

Binary* BinaryParser::get_binary(void) {
  return this->binary_;
}

} // namespace MachO
} // namespace LIEF
