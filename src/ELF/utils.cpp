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
#include <algorithm>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <vector>

#include "LIEF/exception.hpp"

#include "LIEF/ELF/utils.hpp"
#include "LIEF/ELF/Structures.hpp"

namespace LIEF {
namespace ELF {

bool is_elf(const std::string& file) {
  std::ifstream binary(file, std::ios::in | std::ios::binary);
  if (not binary) {
    throw bad_file("Unable to open the file");
  }
  char magic[sizeof(ElfMagic)];

  binary.seekg(0, std::ios::beg);
  binary.read(magic, sizeof(magic));
  return std::equal(std::begin(magic), std::end(magic), std::begin(ElfMagic));
}

bool is_elf(const std::vector<uint8_t>& raw) {

  char magic[sizeof(ElfMagic)];

  if (raw.size() < sizeof(ElfMagic)) {
    return false;
  }


  std::copy(
    reinterpret_cast<const uint8_t*>(raw.data()),
    reinterpret_cast<const uint8_t*>(raw.data()) + sizeof(ElfMagic),
    magic);

  return std::equal(std::begin(magic), std::end(magic), std::begin(ElfMagic));
}

//! SYSV hash function
unsigned long hash32(const char* name) {
  unsigned long h = 0, g;
  while (*name) {
    h = (h << 4) + *name++;
    if ((g = h & 0xf0000000)) {
      h ^= g >> 24;
    }
    h &= ~g;
  }
  return h;
}

//! SYSV hash function
//! https://blogs.oracle.com/ali/entry/gnu_hash_elf_sections
unsigned long hash64(const char* name) {
  unsigned long h = 0, g;
  while (*name) {
    h = (h << 4) + *name++;
    if ((g = h & 0xf0000000)) {
      h ^= g >> 24;
    }
    h &= 0x0fffffff;
  }
  return h;
}

uint32_t dl_new_hash(const char* name) {
  uint32_t h = 5381;

  for (unsigned char c = *name; c != '\0'; c = *++name) {
    h = h * 33 + c;
  }

  return h & 0xffffffff;
}



} // namespace ELF
} // namespace LIEF






