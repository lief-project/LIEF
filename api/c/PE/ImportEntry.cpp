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
#include "ImportEntry.hpp"

namespace LIEF {
namespace PE {

void init_c_import_entries(Pe_Import_t* c_import, Import& imp) {

  Import::it_entries entries = imp.entries();

  c_import->entries = static_cast<Pe_ImportEntry_t**>(
      malloc((entries.size() + 1) * sizeof(Pe_ImportEntry_t**)));

  for (size_t i = 0; i < entries.size(); ++i) {
    ImportEntry& import_entry = entries[i];
    c_import->entries[i] = static_cast<Pe_ImportEntry_t*>(malloc(sizeof(Pe_ImportEntry_t)));

    c_import->entries[i]->is_ordinal    = import_entry.is_ordinal();
    c_import->entries[i]->name          = import_entry.is_ordinal() ? nullptr : import_entry.name().c_str();
    c_import->entries[i]->ordinal       = import_entry.is_ordinal() ? import_entry.ordinal() : 0;
    c_import->entries[i]->hint_name_rva = import_entry.hint_name_rva();
    c_import->entries[i]->hint          = import_entry.hint();
    c_import->entries[i]->iat_value     = import_entry.iat_value();
    c_import->entries[i]->data          = import_entry.data();
    c_import->entries[i]->iat_address   = import_entry.iat_address();
  }

  c_import->entries[entries.size()] = nullptr;

}


void destroy_import_entries(Pe_Import_t* c_import) {
  Pe_ImportEntry_t **entries = c_import->entries;
  for (size_t idx = 0; entries[idx] != nullptr; ++idx) {
    free(entries[idx]);
  }
  free(c_import->entries);

}

}
}
