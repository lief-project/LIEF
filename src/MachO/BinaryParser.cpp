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

BinaryParser::BinaryParser(const std::vector<uint8_t>& data, uint64_t fat_offset) :
  stream_{new VectorStream{data}}
{

  this->binary_ = new Binary{};
  this->binary_->fat_offset_ = fat_offset;
  this->parse();
}


BinaryParser::BinaryParser(std::unique_ptr<VectorStream>&& stream, uint64_t fat_offset) :
  stream_{std::move(stream)}
{

  this->binary_ = new Binary{};
  this->binary_->fat_offset_ = fat_offset;
  this->parse();
}

BinaryParser::BinaryParser(const std::string& file) :
  LIEF::Parser{file}
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

  this->parse();
}


void BinaryParser::parse(void) {
  LOG(DEBUG) << "Parsing MachO" << std::endl;
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
    this->parse_header<MachO64>();
    if (this->binary_->header().nb_cmds() > 0) {
      this->parse_load_commands<MachO64>();
    }
  } else {
    this->parse_header<MachO32>();

    if (this->binary_->header().nb_cmds() > 0) {
      this->parse_load_commands<MachO32>();
    }
  }

}


Binary* BinaryParser::get_binary(void) {
  return this->binary_;
}


std::pair<uint64_t, uint64_t> BinaryParser::decode_uleb128(const VectorStream& stream, uint64_t offset) {
  uint64_t value = 0;
  unsigned shift = 0;
  uint64_t current_offset = offset - sizeof(uint8_t);
  do {
    current_offset += sizeof(uint8_t);
    value += static_cast<uint64_t>(stream.read_integer<uint8_t>(current_offset) & 0x7f) << shift;
    shift += 7;
  } while (stream.read_integer<uint8_t>(current_offset) >= 128);

  uint64_t delta = current_offset - offset;
  delta++;
  return {value, delta};
}


} // namespace MachO
} // namespace LIEF
