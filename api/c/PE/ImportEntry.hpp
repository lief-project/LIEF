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
#ifndef LIEF_PE_IMPORT_ENTRY_CPP_C_API_
#define LIEF_PE_IMPORT_ENTRY_CPP_C_API_

#include "LIEF/PE/Binary.h"
#include "LIEF/PE/Binary.hpp"

#include "LIEF/PE/ImportEntry.h"
#include "LIEF/PE/ImportEntry.hpp"

namespace LIEF {
namespace PE {

void init_c_import_entries(Pe_Import_t* c_import, Import& imp);
void destroy_import_entries(Pe_Import_t* c_import);

}
}

#endif
