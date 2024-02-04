/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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

#include "LIEF/PE/Binary.h"

#include "LIEF/PE/Parser.hpp"
#include "LIEF/PE/Binary.hpp"

#include "Binary.hpp"
#include "DosHeader.hpp"
#include "Header.hpp"
#include "OptionalHeader.hpp"
#include "Section.hpp"
#include "DataDirectory.hpp"
#include "Import.hpp"

using namespace LIEF::PE;

namespace LIEF {
namespace PE {

void init_c_binary(Pe_Binary_t* c_binary, Binary* binary) {
  c_binary->handler = reinterpret_cast<void*>(binary);

  init_c_dos_header(c_binary, binary);
  init_c_header(c_binary, binary);
  init_c_optional_header(c_binary, binary);
  init_c_sections(c_binary, binary);
  init_c_data_directories(c_binary, binary);
  init_c_imports(c_binary, binary);

}

}
}

Pe_Binary_t* pe_parse(const char *file) {
  Binary* binary = Parser::parse(file).release();

  if (binary == nullptr) {
    return nullptr;
  }

  auto* c_binary = static_cast<Pe_Binary_t*>(malloc(sizeof(Pe_Binary_t)));
  std::memset(c_binary, 0, sizeof(Pe_Binary_t));
  init_c_binary(c_binary, binary);

  return c_binary;
}

void pe_binary_destroy(Pe_Binary_t* binary) {
  destroy_sections(binary);
  destroy_data_directories(binary);
  destroy_imports(binary);
  delete reinterpret_cast<Binary*>(binary->handler);
  free(binary);
}
