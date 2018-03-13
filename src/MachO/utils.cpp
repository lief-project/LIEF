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
#include "LIEF/MachO/utils.hpp"
#include "LIEF/MachO/Structures.hpp"

#include "LIEF/exception.hpp"

#include <fstream>
#include <iterator>
#include <string>
#include <stdexcept>
#include <vector>

namespace LIEF {
namespace MachO {

bool is_macho(const std::string& file) {
  std::ifstream binary(file, std::ios::in | std::ios::binary);
  if (not binary) {
    throw LIEF::bad_file("Unable to open the '" + file + "'");
  }

  MACHO_TYPES magic;
  binary.seekg(0, std::ios::beg);
  binary.read(reinterpret_cast<char*>(&magic), sizeof(uint32_t));

  if (magic == MACHO_TYPES::MH_MAGIC or
      magic == MACHO_TYPES::MH_CIGAM or
      magic == MACHO_TYPES::MH_MAGIC_64 or
      magic == MACHO_TYPES::MH_CIGAM_64 or
      magic == MACHO_TYPES::FAT_MAGIC or
      magic == MACHO_TYPES::FAT_CIGAM)
  {
    return true;
  }
  return false;
}

bool is_macho(const std::vector<uint8_t>& raw) {

  if (raw.size() < sizeof(MACHO_TYPES)) {
    return false;
  }

  MACHO_TYPES magic;

  std::copy(
    reinterpret_cast<const uint8_t*>(raw.data()),
    reinterpret_cast<const uint8_t*>(raw.data()) + sizeof(uint32_t),
    reinterpret_cast<uint8_t*>(&magic));

  if (magic == MACHO_TYPES::MH_MAGIC or
      magic == MACHO_TYPES::MH_CIGAM or
      magic == MACHO_TYPES::MH_MAGIC_64 or
      magic == MACHO_TYPES::MH_CIGAM_64 or
      magic == MACHO_TYPES::FAT_MAGIC or
      magic == MACHO_TYPES::FAT_CIGAM)
  {
    return true;
  }
  return false;
}

bool is_fat(const std::string& file) {
  if (not is_macho(file)) {
    throw LIEF::bad_format("'" + file + "' is not a MachO");
  }

  std::ifstream binary(file, std::ios::in | std::ios::binary);

  if (not binary) {
    throw LIEF::bad_file("Unable to open the '" + file + "'");
  }

  MACHO_TYPES magic;
  binary.seekg(0, std::ios::beg);
  binary.read(reinterpret_cast<char*>(&magic), sizeof(uint32_t));

  if (magic == MACHO_TYPES::FAT_MAGIC or
      magic == MACHO_TYPES::FAT_CIGAM)
  {
    return true;
  }

  return false;
}

bool is_64(const std::string& file) {
 if (not is_macho(file)) {
    throw LIEF::bad_format("'" + file + "' is not a MachO");
  }

  std::ifstream binary(file, std::ios::in | std::ios::binary);

  if (not binary) {
    throw LIEF::bad_file("Unable to open the '" + file + "'");
  }

  MACHO_TYPES magic;
  binary.seekg(0, std::ios::beg);
  binary.read(reinterpret_cast<char*>(&magic), sizeof(uint32_t));

  if (magic == MACHO_TYPES::MH_MAGIC_64 or
      magic == MACHO_TYPES::MH_CIGAM_64 )
  {
    return true;
  }
  return false;

}

}
}

