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
#include "LIEF/MachO/Parser.hpp"

#include <algorithm>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <memory>
#include <regex>
#include <stdexcept>

#include "LIEF/BinaryStream/VectorStream.hpp"
#include "LIEF/MachO/Binary.hpp"
#include "LIEF/MachO/BinaryParser.hpp"
#include "LIEF/MachO/FatBinary.hpp"
#include "LIEF/MachO/utils.hpp"
#include "LIEF/exception.hpp"
#include "MachO/Structures.hpp"
#include "logging.hpp"

namespace LIEF {
namespace MachO {
Parser::Parser() = default;
Parser::~Parser() = default;

// From File
Parser::Parser(const std::string& file, const ParserConfig& conf)
    : LIEF::Parser{file}, config_{conf} {
  auto stream = VectorStream::from_file(file);
  if (!stream) {
    LIEF_ERR("Can't create the stream");
  } else {
    stream_ = std::make_unique<VectorStream>(std::move(*stream));
  }
}

std::unique_ptr<FatBinary> Parser::parse(const std::string& filename,
                                         const ParserConfig& conf) {
  if (!is_macho(filename)) {
    LIEF_ERR("{} is not a MachO file", filename);
    return nullptr;
  }

  Parser parser{filename, conf};
  parser.build();
  for (std::unique_ptr<Binary>& binary : parser.binaries_) {
    binary->name(filename);
  }
  return std::unique_ptr<FatBinary>(new FatBinary{std::move(parser.binaries_)});
}

// From Vector
Parser::Parser(std::vector<uint8_t> data, const ParserConfig& conf)
    : stream_{std::make_unique<VectorStream>(std::move(data))}, config_{conf} {}

std::unique_ptr<FatBinary> Parser::parse(const std::vector<uint8_t>& data,
                                         const std::string& name,
                                         const ParserConfig& conf) {
  if (!is_macho(data)) {
    LIEF_ERR("The provided data seem not being related to a MachO binary");
    return nullptr;
  }

  Parser parser{data, conf};
  parser.build();

  for (std::unique_ptr<Binary>& binary : parser.binaries_) {
    binary->name(name);
  }
  return std::unique_ptr<FatBinary>(new FatBinary{std::move(parser.binaries_)});
}

ok_error_t Parser::build_fat() {
  static constexpr size_t MAX_FAT_ARCH = 10;
  stream_->setpos(0);
  const auto header = stream_->read<details::fat_header>();
  if (!header) {
    LIEF_ERR("Can't read the FAT header");
    return make_error_code(lief_errors::read_error);
  }
  uint32_t nb_arch = Swap4Bytes(header->nfat_arch);
  LIEF_DEBUG("In this Fat binary there is #{:d} archs", nb_arch);

  if (nb_arch > MAX_FAT_ARCH) {
    LIEF_ERR("Too many architectures");
    return make_error_code(lief_errors::parsing_error);
  }

  for (size_t i = 0; i < nb_arch; ++i) {
    auto res_arch = stream_->read<details::fat_arch>();
    if (!res_arch) {
      LIEF_ERR("Can't read arch #{}", i);
      break;
    }
    const auto arch = *res_arch;

    const uint32_t offset = BinaryStream::swap_endian(arch.offset);
    const uint32_t size = BinaryStream::swap_endian(arch.size);

    LIEF_DEBUG("Dealing with arch[{:d}]", i);
    LIEF_DEBUG("    [{:d}].offset", offset);
    LIEF_DEBUG("    [{:d}].size", size);

    std::vector<uint8_t> macho_data;
    if (!stream_->peek_data(macho_data, offset, size)) {
      LIEF_ERR("MachO #{:d} is corrupted!", i);
      continue;
    }

    std::unique_ptr<Binary> bin =
        BinaryParser::parse(std::move(macho_data), offset, config_);
    if (bin == nullptr) {
      LIEF_ERR("Can't parse the binary at the index #{:d}", i);
      continue;
    }
    binaries_.push_back(std::move(bin));
  }
  return ok();
}

ok_error_t Parser::build() {
  auto res_type = stream_->peek<uint32_t>();
  if (!res_type) {
    return make_error_code(lief_errors::parsing_error);
  }
  auto type = static_cast<MACHO_TYPES>(*res_type);

  try {
    // Fat binary
    if (type == MACHO_TYPES::FAT_MAGIC || type == MACHO_TYPES::FAT_CIGAM) {
      if (!build_fat()) {
        LIEF_WARN("Errors while parsing the Fat MachO");
      }
    } else {  // fit binary
      std::unique_ptr<Binary> bin =
          BinaryParser::parse(std::move(stream_), 0, config_);
      if (bin == nullptr) {
        return make_error_code(lief_errors::parsing_error);
      }
      binaries_.push_back(std::move(bin));
    }
  } catch (const std::exception& e) {
    LIEF_DEBUG("{}", e.what());
    return make_error_code(lief_errors::parsing_error);
  }

  return ok();
}

}  // namespace MachO
}  // namespace LIEF
