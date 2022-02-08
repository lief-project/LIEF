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
#include "Import.hpp"
#include "ImportEntry.hpp"

namespace LIEF {
namespace PE {

void init_c_imports(Pe_Binary_t* c_binary, Binary* binary) {

  if (!binary->has_imports()) {
    c_binary->imports = nullptr;
  }

  Binary::it_imports imports = binary->imports();

  c_binary->imports = static_cast<Pe_Import_t**>(
      malloc((imports.size() + 1) * sizeof(Pe_Import_t**)));

  for (size_t i = 0; i < imports.size(); ++i) {
    Import& imp = imports[i];
    c_binary->imports[i] = static_cast<Pe_Import_t*>(malloc(sizeof(Pe_Import_t)));

    c_binary->imports[i]->name                     = imp.name().c_str();
    c_binary->imports[i]->forwarder_chain          = imp.forwarder_chain();
    c_binary->imports[i]->timedatestamp            = imp.forwarder_chain();
    c_binary->imports[i]->import_address_table_rva = imp.import_address_table_rva();
    c_binary->imports[i]->import_lookup_table_rva  = imp.import_lookup_table_rva();
    c_binary->imports[i]->entries                  = nullptr;
    init_c_import_entries(c_binary->imports[i], imp);
  }

  c_binary->imports[imports.size()] = nullptr;
}


void destroy_imports(Pe_Binary_t* c_binary) {
  if (c_binary->imports == nullptr) {
    return;
  }

  Pe_Import_t **imports = c_binary->imports;
  for (size_t idx = 0; imports[idx] != nullptr; ++idx) {
    destroy_import_entries(imports[idx]);
    free(imports[idx]);
  }
  free(c_binary->imports);

}

}
}
