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

#include "easylogging++.h"

#include "LIEF/filesystem/filesystem.h"
#include "LIEF/exception.hpp"

#include "LIEF/MachO/Parser.hpp"
#include "LIEF/MachO/BinaryParser.hpp"
#include "LIEF/MachO/utils.hpp"


namespace LIEF {
namespace MachO {
Parser::Parser(void) = default;
Parser::~Parser(void) = default;

Parser::Parser(const std::string& file) :
  LIEF::Parser{file}
{

  if (not is_macho(file)) {
    throw bad_file("'" + file + "' is not a MachO binary");
  }

  this->stream_ = std::unique_ptr<VectorStream>(new VectorStream{file});
  this->build();
}


std::vector<Binary*> Parser::parse(const std::string& filename) {
  Parser parser{filename};
  for (Binary* binary : parser.binaries_) {
    binary->name(filesystem::path(filename).filename());
  }

  return parser.binaries_;
}


void Parser::build_fat(void) {

  const fat_header *header = reinterpret_cast<const fat_header*>(
      this->stream_->read(0, sizeof(fat_header)));
  uint32_t nb_arch = Swap4Bytes(header->nfat_arch);
  LOG(DEBUG) << "In this Fat binary there is " << std::dec << nb_arch << " archs" << std::endl;

  if (nb_arch > 10) {
    throw parser_error("Too much architectures");
  }

  const fat_arch* arch = reinterpret_cast<const fat_arch*>(
      this->stream_->read(sizeof(fat_header), sizeof(fat_arch)));

  for (size_t i = 0; i < nb_arch; ++i) {

    const uint32_t offset = BinaryStream::swap_endian(arch[i].offset);
    const uint32_t size   = BinaryStream::swap_endian(arch[i].size);

    LOG(DEBUG) << "Dealing with arch[" << std::dec << i << "]" << std::endl;
    LOG(DEBUG) << "[" << std::dec << i << "] offset: 0x" << std::hex << offset << std::endl;
    LOG(DEBUG) << "[" << std::dec << i << "] size:   0x" << std::hex << size << std::endl;

    const uint8_t* raw = reinterpret_cast<const uint8_t*>(
      this->stream_->read(offset, size));

    std::vector<uint8_t> data = {raw, raw + size};

    Binary *binary = BinaryParser{std::move(data), offset}.get_binary();
    this->binaries_.push_back(binary);
  }
}

void Parser::build(void) {
  MACHO_TYPES type = static_cast<MACHO_TYPES>(
      *reinterpret_cast<const uint32_t*>(this->stream_->read(0, sizeof(uint32_t))));

  // Fat binary
  if (type == MACHO_TYPES::FAT_MAGIC or
      type == MACHO_TYPES::FAT_CIGAM) {
    this->build_fat();
  } else { // fit binary
    Binary *binary = BinaryParser(std::move(this->stream_)).get_binary();
    this->binaries_.push_back(binary);
  }
}

} //namespace MachO
}
