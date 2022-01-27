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
#include <fstream>
#include <iterator>
#include <iostream>
#include <algorithm>
#include <memory>
#include <stdexcept>

#include "BinaryParser.tcc"

#include "LIEF/BinaryStream/VectorStream.hpp"
#include "LIEF/exception.hpp"

#include "LIEF/MachO/BinaryParser.hpp"

#include "LIEF/MachO/utils.hpp"
#include "LIEF/MachO/Header.hpp"
#include "LIEF/MachO/LoadCommand.hpp"
#include "LIEF/MachO/SegmentCommand.hpp"
#include "LIEF/MachO/Section.hpp"
#include "LIEF/MachO/UUIDCommand.hpp"
#include "LIEF/MachO/SymbolCommand.hpp"
#include "LIEF/MachO/Symbol.hpp"
#include "LIEF/MachO/EnumToString.hpp"
#include "LIEF/MachO/ExportInfo.hpp"

#include "filesystem/filesystem.h"

namespace LIEF {
namespace MachO {

BinaryParser::BinaryParser() = default;
BinaryParser::~BinaryParser() = default;

BinaryParser::BinaryParser(const std::vector<uint8_t>& data, uint64_t fat_offset, const ParserConfig& conf) :
  stream_{new VectorStream{data}},
  binary_{new Binary{}},
  config_{conf}
{
  binary_->fat_offset_ = fat_offset;
  init();
}


BinaryParser::BinaryParser(std::unique_ptr<BinaryStream>&& stream, uint64_t fat_offset, const ParserConfig& conf) :
  stream_{std::move(stream)},
  binary_{new Binary{}},
  config_{conf}
{

  binary_->fat_offset_ = fat_offset;
  init();
}

BinaryParser::BinaryParser(const std::string& file, const ParserConfig& conf) :
  LIEF::Parser{file},
  config_{conf}
{

  if (!is_macho(file)) {
    throw bad_file("'" + file + "' is not a MachO binary");
  }


  if (!is_fat(file)) {
    throw bad_file("'" + file + "' is a FAT MachO, this parser takes fit binary");
  }

  stream_ = std::make_unique<VectorStream>(file);

  binary_ = new Binary{};
  binary_->name_ = filesystem::path(file).filename();
  binary_->fat_offset_ = 0;

  init();
}

void BinaryParser::init() {
  LIEF_DEBUG("Parsing MachO");
  try {
    auto type = static_cast<MACHO_TYPES>(stream_->peek<uint32_t>());
    is64_ = type == MACHO_TYPES::MH_MAGIC_64 ||
            type == MACHO_TYPES::MH_CIGAM_64;

    binary_->is64_ = is64_;
    type_          = type;

    is64_ ? parse<details::MachO64>() :
            parse<details::MachO32>();
  } catch (const std::exception& e) {
    LIEF_DEBUG("{}", e.what());
  }

}


void BinaryParser::parse_export_trie(uint64_t start, uint64_t end, const std::string& prefix) {
  if (stream_->pos() >= end) {
    return;
  }

  if (start > stream_->pos()) {
    return;
  }

  const auto terminal_size = stream_->read<uint8_t>();
  uint64_t children_offset = stream_->pos() + terminal_size;

  if (terminal_size != 0) {
    uint64_t offset = stream_->pos() - start;

    uint64_t flags   = stream_->read_uleb128();
    //uint64_t address = stream_->read_uleb128();

    const std::string& symbol_name = prefix;
    std::unique_ptr<ExportInfo> export_info{new ExportInfo{0, flags, offset}};
    Symbol* symbol = nullptr;
    auto search = memoized_symbols_.find(symbol_name);
    if (search != memoized_symbols_.end()) {
      symbol = search->second;
    } else {
      symbol = binary_->get_symbol(symbol_name);
    }
    if (symbol != nullptr) {
      export_info->symbol_ = symbol;
      symbol->export_info_ = export_info.get();
    } else { // Register it into the symbol table
      std::unique_ptr<Symbol> symbol{new Symbol{}};
      symbol->origin_            = SYMBOL_ORIGINS::SYM_ORIGIN_DYLD_EXPORT;
      symbol->value_             = 0;
      symbol->type_              = 0;
      symbol->numberof_sections_ = 0;
      symbol->description_       = 0;
      symbol->name(symbol_name);

      // Weak bind of the pointer
      symbol->export_info_       = export_info.get();
      export_info->symbol_       = symbol.get();
      binary_->symbols_.push_back(symbol.release());
    }

    // REEXPORT
    // ========
    if (export_info->has(EXPORT_SYMBOL_FLAGS::EXPORT_SYMBOL_FLAGS_REEXPORT)) {
      const uint64_t ordinal = stream_->read_uleb128();
      export_info->other_ = ordinal;

      std::string imported_name = stream_->peek_string();
      if (imported_name.empty()) {
        imported_name = export_info->symbol().name();
      }

      Symbol* symbol = nullptr;
      auto search = memoized_symbols_.find(imported_name);
      if (search != memoized_symbols_.end()) {
        symbol = search->second;
      } else {
        symbol = binary_->get_symbol(imported_name);
      }
      if (symbol != nullptr) {
        export_info->alias_  = symbol;
        symbol->export_info_ = export_info.get();
        symbol->value_       = export_info->address();
      } else {
        std::unique_ptr<Symbol> symbol{new Symbol{}};
        symbol->origin_            = SYMBOL_ORIGINS::SYM_ORIGIN_DYLD_EXPORT;
        symbol->value_             = export_info->address();
        symbol->type_              = 0;
        symbol->numberof_sections_ = 0;
        symbol->description_       = 0;
        symbol->name(symbol_name);

        // Weak bind of the pointer
        symbol->export_info_      = export_info.get();
        export_info->alias_       = symbol.get();
        binary_->symbols_.push_back(symbol.release());
      }


      if (ordinal < binary_->libraries().size()) {
        DylibCommand& lib = binary_->libraries()[ordinal];
        export_info->alias_location_ = &lib;
      } else {
        // TODO: Corrupted library name
      }
    } else {
      uint64_t address = stream_->read_uleb128();
      export_info->address(address);
    }

    // STUB_AND_RESOLVER
    // =================
    if (export_info->has(EXPORT_SYMBOL_FLAGS::EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER)) {
      export_info->other_ = stream_->read_uleb128();
    }

    binary_->dyld_info().export_info_.push_back(export_info.release());

  }
  stream_->setpos(children_offset);
  const auto nb_children = stream_->read<uint8_t>();
  for (size_t i = 0; i < nb_children; ++i) {
    std::string suffix = stream_->read_string();
    std::string name   = prefix + suffix;

    auto child_node_offet = static_cast<uint32_t>(stream_->read_uleb128());

    if (child_node_offet == 0) {
      break;
    }

    if (visited_.count(start + child_node_offet) > 0) {
      break;
    }
    visited_.insert(start + child_node_offet);
    size_t current_pos = stream_->pos();
    stream_->setpos(start + child_node_offet);
    parse_export_trie(start, end, name);
    stream_->setpos(current_pos);
  }

}

void BinaryParser::parse_dyldinfo_export() {

  DyldInfo& dyldinfo = binary_->dyld_info();

  uint32_t offset = std::get<0>(dyldinfo.export_info());
  uint32_t size   = std::get<1>(dyldinfo.export_info());

  if (offset == 0 || size == 0) {
    return;
  }

  uint64_t end_offset = offset + size;

  try {
    const auto* raw_trie = stream_->peek_array<uint8_t>(offset, size, /* check */ false);
    if (raw_trie != nullptr) {
      dyldinfo.export_trie({raw_trie, raw_trie + size});
    }
  } catch (const exception& e) {
    LIEF_DEBUG("{}", e.what());
  }

  stream_->setpos(offset);
  parse_export_trie(offset, end_offset, "");
}

Binary* BinaryParser::get_binary() {
  return binary_;
}

} // namespace MachO
} // namespace LIEF
