
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
#include <string>
#include "LIEF/OAT/utils.hpp"
#include "LIEF/OAT/Structures.hpp"

#include "LIEF/ELF.hpp"


namespace LIEF {
namespace OAT {

bool is_oat(const std::string& file) {
  if (not LIEF::ELF::is_elf(file)) {
    return false;
  }

  std::unique_ptr<const LIEF::ELF::Binary> elf_binary;
  try {
    elf_binary = std::unique_ptr<const LIEF::ELF::Binary>{LIEF::ELF::Parser::parse(file)};
  } catch (const LIEF::exception&) {
    return false;
  }

  return is_oat(*elf_binary);

}


bool is_oat(const std::vector<uint8_t>& raw) {
  std::unique_ptr<const LIEF::ELF::Binary> elf_binary;
  try {
    elf_binary = std::unique_ptr<const LIEF::ELF::Binary>{LIEF::ELF::Parser::parse(raw)};
  } catch (const LIEF::exception&) {
    return false;
  }
  return is_oat(*elf_binary);
}

bool is_oat(const ELF::Binary& elf_binary) {
  LIEF::ELF::it_const_symbols dynamic_symbols = elf_binary.dynamic_symbols();

  auto&& it_oatdata_symbol = std::find_if(
      std::begin(dynamic_symbols),
      std::end(dynamic_symbols),
      [] (const LIEF::ELF::Symbol& sym) {
        return sym.name() == "oatdata";
      });

  if (it_oatdata_symbol == std::end(dynamic_symbols)) {
    return false;
  }

  const std::vector<uint8_t>& header = elf_binary.get_content_from_virtual_address(it_oatdata_symbol->value(), sizeof(oat_magic));
  return std::equal(
      header.data(),
      header.data() + sizeof(oat_magic),
      std::begin(oat_magic));
}

oat_version_t version(const std::string& file) {
  if (not is_oat(file)) {
    return 0;
  }

  std::unique_ptr<const LIEF::ELF::Binary> elf_binary;
  try {
    elf_binary = std::unique_ptr<const LIEF::ELF::Binary>{LIEF::ELF::Parser::parse(file)};
  } catch (const LIEF::exception&) {
    return 0;
  }

  return version(*elf_binary);
}

oat_version_t version(const std::vector<uint8_t>& raw) {
  if (not is_oat(raw)) {
    return 0;
  }

  std::unique_ptr<const LIEF::ELF::Binary> elf_binary;
  try {
    elf_binary = std::unique_ptr<const LIEF::ELF::Binary>{LIEF::ELF::Parser::parse(raw)};
  } catch (const LIEF::exception&) {
    return 0;
  }

  return version(*elf_binary);
}


oat_version_t version(const LIEF::ELF::Binary& elf_binary) {

  const LIEF::ELF::Symbol& oatdata_symbol = dynamic_cast<const LIEF::ELF::Symbol&>(elf_binary.get_symbol("oatdata"));

  const std::vector<uint8_t>& header = elf_binary.get_content_from_virtual_address(oatdata_symbol.value() + sizeof(oat_magic), sizeof(oat_version));

  uint32_t version = std::stoul(std::string(reinterpret_cast<const char*>(header.data()), 3));

  return version;
}

LIEF::Android::ANDROID_VERSIONS android_version(oat_version_t version) {
  static const std::map<oat_version_t, LIEF::Android::ANDROID_VERSIONS> oat2android {
    { 64,  LIEF::Android::ANDROID_VERSIONS::VERSION_601 },
    { 79,  LIEF::Android::ANDROID_VERSIONS::VERSION_700 },
    { 88,  LIEF::Android::ANDROID_VERSIONS::VERSION_712 },
    { 124, LIEF::Android::ANDROID_VERSIONS::VERSION_800 },
    { 131, LIEF::Android::ANDROID_VERSIONS::VERSION_810 },

  };
  auto   it  = oat2android.lower_bound(version);
  return it == oat2android.end() ? LIEF::Android::ANDROID_VERSIONS::VERSION_UNKNOWN : it->second;
}




} // namespace OAT
} // namespace LIEF






