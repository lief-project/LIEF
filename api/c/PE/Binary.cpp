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
#include "LIEF/PE/Binary.h"

#include <cstring>

#include "Binary.hpp"
#include "DataDirectory.hpp"
#include "DosHeader.hpp"
#include "Header.hpp"
#include "Import.hpp"
#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/Parser.hpp"
#include "OptionalHeader.hpp"
#include "Section.hpp"

using namespace LIEF::PE;

namespace LIEF {
namespace PE {

void init_c_binary(Pe_Binary_t* c_binary, Binary* binary) {
  c_binary->name = binary->name().c_str();
  c_binary->handler = reinterpret_cast<void*>(binary);

  init_c_dos_header(c_binary, binary);
  init_c_header(c_binary, binary);
  init_c_optional_header(c_binary, binary);
  init_c_sections(c_binary, binary);
  init_c_data_directories(c_binary, binary);
  init_c_imports(c_binary, binary);
}

}  // namespace PE
}  // namespace LIEF

Pe_Binary_t* pe_parse(const char* file) {
  Binary* binary = Parser::parse(file).release();
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
