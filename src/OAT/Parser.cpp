/* Copyright 2021 R. Thomas
 * Copyright 2021 Quarkslab
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

#include "LIEF/OAT/Parser.hpp"
#include "LIEF/OAT/utils.hpp"
#include "LIEF/OAT/Structures.hpp"

#include "LIEF/VDEX.hpp"

#include "filesystem/filesystem.h"

#include "Parser.tcc"

namespace LIEF {
namespace OAT {

Parser::~Parser(void) = default;
Parser::Parser(void)  = default;


std::unique_ptr<Binary> Parser::parse(const std::string& oat_file) {
  if (not is_oat(oat_file)) {
    LIEF_ERR("{} is not an OAT", oat_file);
    return nullptr;
  }

  Parser parser{oat_file};
  parser.init(oat_file);
  return std::unique_ptr<Binary>{parser.oat_binary_};
}


std::unique_ptr<Binary> Parser::parse(const std::string& oat_file, const std::string& vdex_file) {
  if (not is_oat(oat_file)) {
    return nullptr;
  }

  if (not VDEX::is_vdex(vdex_file)) {
    return nullptr;
  }
  Parser parser{oat_file};
  parser.set_vdex(VDEX::Parser::parse(vdex_file).release());
  parser.init(oat_file);
  return std::unique_ptr<Binary>{parser.oat_binary_};

}

std::unique_ptr<Binary> Parser::parse(const std::vector<uint8_t>& data, const std::string& name) {
  Parser parser{data, name};
  parser.init(name);
  return std::unique_ptr<Binary>{parser.oat_binary_};
}


Parser::Parser(const std::vector<uint8_t>& data, const std::string& name) :
  oat_binary_{new Binary{}},
  stream_{nullptr}
{
  LIEF::ELF::Parser{data, name, LIEF::ELF::DYNSYM_COUNT_METHODS::COUNT_AUTO, this->oat_binary_};
}

Parser::Parser(const std::string& file) :
  LIEF::Parser{file},
  oat_binary_{new Binary{}},
  stream_{nullptr}
{
  LIEF::ELF::Parser{file, LIEF::ELF::DYNSYM_COUNT_METHODS::COUNT_AUTO, this->oat_binary_};
}


bool Parser::has_vdex(void) const {
  return this->vdex_file_ != nullptr;
}

void Parser::set_vdex(VDEX::File* file) {
  this->vdex_file_ = file;
}


void Parser::init(const std::string& name) {
  LIEF_DEBUG("Parsing {}", name);

  oat_version_t version = OAT::version(*this->oat_binary_);

  if (this->has_vdex()) {
    this->oat_binary_->vdex_ = this->vdex_file_;
  }

  if (not this->has_vdex() and version > OAT_088::oat_version) {
    LIEF_INFO("No VDEX provided with this OAT file. Parsing will be incomplete");
  }

  if (version <= OAT_064::oat_version) {
    return this->parse_binary<OAT64_t>();
  }

  if (version <= OAT_079::oat_version) {
    return this->parse_binary<OAT79_t>();
  }

  if (version <= OAT_088::oat_version) {
    return this->parse_binary<OAT88_t>();
  }

  if (version <= OAT_124::oat_version) {
    return this->parse_binary<OAT124_t>();
  }

  if (version <= OAT_131::oat_version) {
    return this->parse_binary<OAT131_t>();
  }

  if (version <= OAT_138::oat_version) {
    return this->parse_binary<OAT138_t>();
  }

}


void Parser::bind_vdex(void) {
  if (this->vdex_file_ == nullptr) {
    LIEF_WARN("Inconsistent state: vdex_file is null");
    return;
  }
  for (DEX::File& dex_file : this->vdex_file_->dex_files()) {
    this->oat_binary_->dex_files_.push_back(&dex_file);
  }
}


} // namespace OAT
} // namespace LIEF
