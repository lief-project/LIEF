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

#include "LIEF/logging++.hpp"
#include "LIEF/filesystem/filesystem.h"

#include "LIEF/ART/Parser.hpp"
#include "LIEF/ART/utils.hpp"
#include "LIEF/ART/Structures.hpp"

#include "Header.tcc"
#include "Parser.tcc"

namespace LIEF {
namespace ART {

Parser::~Parser(void) = default;
Parser::Parser(void)  = default;

File* Parser::parse(const std::string& filename) {
  Parser parser{filename};
  return parser.file_;
}

File* Parser::parse(const std::vector<uint8_t>& data, const std::string& name) {
  Parser parser{data, name};
  return parser.file_;
}


Parser::Parser(const std::vector<uint8_t>& data, const std::string& name) :
  file_{new File{}},
  stream_{std::unique_ptr<VectorStream>(new VectorStream{data})}
{
  if (not is_art(data)) {
    LOG(FATAL) << "'" + name + "' is not an ART file";
    delete this->file_;
    this->file_ = nullptr;
    return;
  }

  art_version_t version = ART::version(data);
  this->init(name, version);
}

Parser::Parser(const std::string& file) :
  file_{new File{}},
  stream_{std::unique_ptr<VectorStream>(new VectorStream{file})}
{
  if (not is_art(file)) {
    LOG(FATAL) << "'" + file + "' is not an ART file";
    delete this->file_;
    this->file_ = nullptr;
    return;
  }

  art_version_t version = ART::version(file);
  this->init(filesystem::path(file).filename(), version);
}


void Parser::init(const std::string& name, art_version_t version) {

  if (version <= ART_17::art_version) {
    return this->parse_file<ART17>();
  }

  if (version <= ART_29::art_version) {
    return this->parse_file<ART29>();
  }

  if (version <= ART_30::art_version) {
    return this->parse_file<ART30>();
  }

  if (version <= ART_44::art_version) {
    return this->parse_file<ART44>();
  }

  if (version <= ART_46::art_version) {
    return this->parse_file<ART46>();
  }
}

} // namespace ART
} // namespace LIEF
