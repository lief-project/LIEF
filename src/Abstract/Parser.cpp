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
#include "LIEF/Abstract/Parser.hpp"

#include "LIEF/OAT.hpp"

#include "LIEF/ELF/utils.hpp"
#include "LIEF/ELF/Parser.hpp"

#include "LIEF/PE/utils.hpp"
#include "LIEF/PE/Parser.hpp"

#include "LIEF/MachO/utils.hpp"
#include "LIEF/MachO/Parser.hpp"

#include "LIEF/exception.hpp"

namespace LIEF {
Parser::~Parser(void) = default;
Parser::Parser(void) :
  binary_size_{0},
  binary_name_{""}
{}

Binary* Parser::parse(const std::string& filename) {

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
    MachO::FatBinary* fat = MachO::Parser::parse(filename);
    MachO::Binary* binary_return = nullptr;
    if (fat) {
      binary_return = fat->pop_back();
      delete fat;
    }
    return binary_return;
  }
#endif

  throw bad_file("Unknown format");

}

Binary* Parser::parse(const std::vector<uint8_t>& raw, const std::string& name) {

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
    MachO::FatBinary* fat = MachO::Parser::parse(raw, name);
    MachO::Binary* binary_return = fat->pop_back();
    delete fat;
    return binary_return;
  }
#endif

  throw bad_file("Unknown format");

}

Parser::Parser(const std::string& filename) :
  binary_size_{0},
  binary_name_{filename}
{
  std::ifstream file(filename, std::ios::in | std::ios::binary);

  if (file) {
    file.unsetf(std::ios::skipws);
    file.seekg(0, std::ios::end);
    this->binary_size_ = static_cast<uint64_t>(file.tellg());
    file.seekg(0, std::ios::beg);
  } else {
    throw LIEF::bad_file("Unable to open " + filename);
  }
}

}
