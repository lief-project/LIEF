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
#include <regex>
#include <stdexcept>
#include <functional>

#include "logging.hpp"

#include "LIEF/exception.hpp"
#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/MachO/Structures.hpp"
#include "LIEF/MachO/FatBinary.hpp"
#include "LIEF/MachO/Binary.hpp"
#include "LIEF/MachO/Parser.hpp"
#include "LIEF/MachO/BinaryParser.hpp"
#include "LIEF/MachO/utils.hpp"

#include "filesystem/filesystem.h"

namespace LIEF {
namespace MachO {
Parser::Parser() = default;
Parser::~Parser() = default;


// From File
Parser::Parser(const std::string& file, const ParserConfig& conf) :
  LIEF::Parser{file},
  stream_{std::make_unique<VectorStream>(file)},
  config_{conf}
{
  build();
  for (Binary* binary : binaries_) {
    binary->name(filesystem::path(file).filename());
  }

}


std::unique_ptr<FatBinary> Parser::parse(const std::string& filename, const ParserConfig& conf) {
  if (!is_macho(filename)) {
    throw bad_file("'" + filename + "' is not a MachO binary");
  }

  Parser parser{filename, conf};
  return std::unique_ptr<FatBinary>{new FatBinary{parser.binaries_}};
}

// From Vector
Parser::Parser(const std::vector<uint8_t>& data, const std::string& name, const ParserConfig& conf) :
  stream_{std::make_unique<VectorStream>(data)},
  config_{conf}
{
  build();

  for (Binary* binary : binaries_) {
    binary->name(name);
  }
}


std::unique_ptr<FatBinary> Parser::parse(const std::vector<uint8_t>& data, const std::string& name, const ParserConfig& conf) {
  if (!is_macho(data)) {
    throw bad_file("'" + name + "' is not a MachO binary");
  }

  Parser parser{data, name, conf};
  return std::unique_ptr<FatBinary>{new FatBinary{parser.binaries_}};
}



void Parser::build_fat() {

  const auto header = stream_->peek<details::fat_header>(0);
  uint32_t nb_arch = Swap4Bytes(header.nfat_arch);
  LIEF_DEBUG("In this Fat binary there is #{:d} archs", nb_arch);

  if (nb_arch > 10) {
    throw parser_error("Too much architectures");
  }

  const auto* arch = stream_->peek_array<details::fat_arch>(sizeof(details::fat_header),
                                                            nb_arch, /* check */ false);

  for (size_t i = 0; i < nb_arch; ++i) {
    const uint32_t offset = BinaryStream::swap_endian(arch[i].offset);
    const uint32_t size   = BinaryStream::swap_endian(arch[i].size);

    LIEF_DEBUG("Dealing with arch[{:d}]", i);
    LIEF_DEBUG("    [{:d}].offset", offset);
    LIEF_DEBUG("    [{:d}].size",   size);

    const auto* raw = stream_->peek_array<uint8_t>(offset, size, /* check */ false);

    if (raw == nullptr) {
      LIEF_ERR("MachO #{:d} is corrupted!", i);
      continue;
    }

    std::vector<uint8_t> data = {raw, raw + size};

    Binary *binary = BinaryParser{std::move(data), offset, config_}.get_binary();
    binaries_.push_back(binary);
  }
}

void Parser::build() {
  try {
    auto type = static_cast<MACHO_TYPES>(stream_->peek<uint32_t>(0));

    // Fat binary
    if (type == MACHO_TYPES::FAT_MAGIC ||
        type == MACHO_TYPES::FAT_CIGAM) {
      build_fat();
    } else { // fit binary
      Binary *binary = BinaryParser(std::move(stream_), 0, config_).get_binary();
      binaries_.push_back(binary);
    }
  } catch (const std::exception& e) {
    LIEF_DEBUG("{}", e.what());
  }
}

} //namespace MachO
}
