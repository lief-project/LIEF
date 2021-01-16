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

#include "logging.hpp"

#include "LIEF/VDEX/Parser.hpp"
#include "LIEF/VDEX/utils.hpp"
#include "LIEF/VDEX/Structures.hpp"

#include "filesystem/filesystem.h"

#include "Header.tcc"
#include "Parser.tcc"

namespace LIEF {
namespace VDEX {

Parser::~Parser(void) = default;
Parser::Parser(void)  = default;

std::unique_ptr<File> Parser::parse(const std::string& filename) {
  Parser parser{filename};
  return std::unique_ptr<File>{parser.file_};
}

std::unique_ptr<File> Parser::parse(const std::vector<uint8_t>& data, const std::string& name) {
  Parser parser{data, name};
  return std::unique_ptr<File>{parser.file_};
}


Parser::Parser(const std::vector<uint8_t>& data, const std::string& name) :
  file_{new File{}},
  stream_{std::unique_ptr<VectorStream>(new VectorStream{data})}
{
  if (not is_vdex(data)) {
    LIEF_ERR("{} is not a VDEX file!", name);
    delete this->file_;
    this->file_ = nullptr;
    return;
  }

  vdex_version_t version = VDEX::version(data);
  this->init(name, version);
}

Parser::Parser(const std::string& file) :
  file_{new File{}},
  stream_{std::unique_ptr<VectorStream>(new VectorStream{file})}
{
  if (not is_vdex(file)) {
    LIEF_ERR("{} is not a VDEX file!", file);
    delete this->file_;
    this->file_ = nullptr;
    return;
  }

  vdex_version_t version = VDEX::version(file);
  this->init(filesystem::path(file).filename(), version);
}


void Parser::init(const std::string& /*name*/, vdex_version_t version) {
  LIEF_DEBUG("VDEX version: {:d}", version);

  if (version <= VDEX_6::vdex_version) {
    return this->parse_file<VDEX6>();
  }

  if (version <= VDEX_10::vdex_version) {
    return this->parse_file<VDEX10>();
  }

  if (version <= VDEX_11::vdex_version) {
    return this->parse_file<VDEX11>();
  }
}

} // namespace VDEX
} // namespace LIEF
