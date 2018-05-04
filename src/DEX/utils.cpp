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

#include "LIEF/DEX/utils.hpp"
#include "LIEF/DEX/Structures.hpp"

namespace LIEF {
namespace DEX {
bool is_dex(const std::string& file) {
  if (std::ifstream ifs{file, std::ios::in | std::ios::binary}) {

    char magic[sizeof(DEX::magic)];

    ifs.seekg(0, std::ios::beg);
    ifs.read(magic, sizeof(magic));

    return std::equal(
        std::begin(magic),
        std::end(magic),
        std::begin(DEX::magic));

  }

  return false;
}

bool is_dex(const std::vector<uint8_t>& raw) {

  if (raw.size() < sizeof(DEX::magic)) {
    return false;
  }

  char magic[sizeof(DEX::magic)];
  std::copy(
    reinterpret_cast<const uint8_t*>(raw.data()),
    reinterpret_cast<const uint8_t*>(raw.data()) + sizeof(DEX::magic),
    magic);

  return std::equal(std::begin(magic), std::end(magic), std::begin(DEX::magic));

}

dex_version_t version(const std::string& file) {
  if (not is_dex(file)) {
    return 0;
  }

  if (std::ifstream ifs{file, std::ios::in | std::ios::binary}) {

    char version[4];

    ifs.seekg(sizeof(DEX::magic), std::ios::beg);
    ifs.read(version, sizeof(version));

    if (std::all_of(std::begin(version), std::end(version) - 1, ::isdigit)) {
      return static_cast<dex_version_t>(std::stoul(version));
    }
    return 0;

  }
  return 0;
}

dex_version_t version(const std::vector<uint8_t>& raw) {
  if (raw.size() < 8) {
    return 0;
  }

  char version[4];
  std::copy(
    reinterpret_cast<const uint8_t*>(raw.data()) + sizeof(DEX::magic),
    reinterpret_cast<const uint8_t*>(raw.data()) + sizeof(DEX::magic) + sizeof(version),
    version);


  if (std::all_of(std::begin(version), std::end(version) - 1, ::isdigit)) {
    return static_cast<dex_version_t>(std::stoul(version));
  }

  return 0;

}


}
}
