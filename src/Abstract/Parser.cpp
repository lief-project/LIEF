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

#include "LIEF/Abstract/Parser.hpp"

#include <fstream>

#include "LIEF/OAT.hpp"
#include "logging.hpp"

#if defined(LIEF_ELF_SUPPORT)
#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/Parser.hpp"
#include "LIEF/ELF/utils.hpp"
#endif

#if defined(LIEF_PE_SUPPORT)
#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/Parser.hpp"
#include "LIEF/PE/utils.hpp"
#endif

#if defined(LIEF_MACHO_SUPPORT)
#include "LIEF/MachO/Binary.hpp"
#include "LIEF/MachO/FatBinary.hpp"
#include "LIEF/MachO/Parser.hpp"
#include "LIEF/MachO/utils.hpp"
#endif

#include "LIEF/exception.hpp"

namespace LIEF {
Parser::~Parser() = default;
Parser::Parser() = default;

std::unique_ptr<Binary> Parser::parse(const std::string& filename) {
#if defined(LIEF_OAT_SUPPORT)
  if (OAT::is_oat(filename)) {
    return OAT::Parser::parse(filename);
  }
#endif

#if defined(LIEF_ELF_SUPPORT)
  if (ELF::is_elf(filename)) {
    return ELF::Parser::parse(filename);
  }
#endif

#if defined(LIEF_PE_SUPPORT)
  if (PE::is_pe(filename)) {
    return PE::Parser::parse(filename);
  }
#endif

#if defined(LIEF_MACHO_SUPPORT)
  if (MachO::is_macho(filename)) {
    // For fat binary we take the last one...
    std::unique_ptr<MachO::FatBinary> fat = MachO::Parser::parse(filename);
    if (fat != nullptr) {
      return fat->pop_back();
    }
    return nullptr;
  }
#endif

  LIEF_ERR("Unknown format");
  return nullptr;
}

std::unique_ptr<Binary> Parser::parse(const std::vector<uint8_t>& raw,
                                      const std::string& name) {
#if defined(LIEF_OAT_SUPPORT)
  if (OAT::is_oat(raw)) {
    return OAT::Parser::parse(raw, name);
  }
#endif

#if defined(LIEF_ELF_SUPPORT)
  if (ELF::is_elf(raw)) {
    return ELF::Parser::parse(raw, name);
  }
#endif

#if defined(LIEF_PE_SUPPORT)
  if (PE::is_pe(raw)) {
    return PE::Parser::parse(raw, name);
  }
#endif

#if defined(LIEF_MACHO_SUPPORT)
  if (MachO::is_macho(raw)) {
    // For fat binary we take the last one...
    std::unique_ptr<MachO::FatBinary> fat = MachO::Parser::parse(raw, name);
    if (fat != nullptr) {
      return fat->pop_back();
    }
    return nullptr;
  }
#endif

  LIEF_ERR("Unknown format");
  return nullptr;
}

Parser::Parser(const std::string& filename) : binary_name_{filename} {
  std::ifstream file(filename, std::ios::in | std::ios::binary);

  if (!file) {
    LIEF_ERR("Can't open '{}'", filename);
    return;
  }
  file.unsetf(std::ios::skipws);
  file.seekg(0, std::ios::end);
  binary_size_ = static_cast<uint64_t>(file.tellg());
  file.seekg(0, std::ios::beg);
}

}  // namespace LIEF
