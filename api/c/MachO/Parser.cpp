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
#include <cstring>

#include "LIEF/MachO/Binary.h"
#include "LIEF/MachO/Parser.hpp"

#include "Binary.hpp"

using namespace LIEF::MachO;

Macho_Binary_t** macho_parse(const char *file) {
  FatBinary* macho_binaries = Parser::parse(file);

  Macho_Binary_t** c_macho_binaries = static_cast<Macho_Binary_t**>(
      malloc((macho_binaries->size() + 1) * sizeof(Macho_Binary_t**)));

  for (size_t i = 0; i < macho_binaries->size(); ++i) {
    Binary& binary = (*macho_binaries)[i];
    c_macho_binaries[i] = static_cast<Macho_Binary_t*>(malloc(sizeof(Macho_Binary_t)));
    init_c_binary(c_macho_binaries[i], &binary);
  }

  c_macho_binaries[macho_binaries->size()] = nullptr;

  return c_macho_binaries;
}

