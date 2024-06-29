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
#include "Symbol.hpp"

namespace LIEF {
namespace MachO {
void init_c_symbols(Macho_Binary_t* c_binary, Binary* binary) {
  Binary::it_symbols symbols = binary->symbols();

  c_binary->symbols = static_cast<Macho_Symbol_t**>(
      malloc((symbols.size() + 1) * sizeof(Macho_Symbol_t**)));

  for (size_t i = 0; i < symbols.size(); ++i) {
    const Symbol& symbol = symbols[i];

    c_binary->symbols[i] = static_cast<Macho_Symbol_t*>(malloc(sizeof(Macho_Symbol_t)));

    c_binary->symbols[i]->name              = symbol.name().c_str();
    c_binary->symbols[i]->type              = symbol.raw_type();
    c_binary->symbols[i]->numberof_sections = symbol.numberof_sections();
    c_binary->symbols[i]->description       = symbol.description();
    c_binary->symbols[i]->value             = symbol.value();
  }

  c_binary->symbols[symbols.size()] = nullptr;

}



void destroy_symbols(Macho_Binary_t* c_binary) {
  Macho_Symbol_t **symbols = c_binary->symbols;
  for (size_t idx = 0; symbols[idx] != nullptr; ++idx) {
    free(symbols[idx]);
  }
  free(c_binary->symbols);

}

}
}


