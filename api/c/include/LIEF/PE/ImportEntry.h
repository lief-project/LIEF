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
#ifndef C_LIEF_PE_IMPORT_ENTRY_H_
#define C_LIEF_PE_IMPORT_ENTRY_H_

#include <inttypes.h>

#include "LIEF/types.h"

#include "LIEF/PE/enums.h"
#include "LIEF/PE/ImportEntry.h"

/**  @defgroup pe_import_entry_c_api Import Entry
 *  @ingroup pe_c_api
 *  @addtogroup pe_import_entry_c_api
 *  @brief Import Entry C API
 *
 *  @{
 */

#ifdef __cplusplus
extern "C" {
#endif

struct Pe_ImportEntry_t {
  bool        is_ordinal;
  const char* name;
  uint16_t    ordinal;
  uint64_t    hint_name_rva;
  uint16_t    hint;
  uint64_t    iat_value;
  uint64_t    data;
  uint64_t    iat_address;
};

typedef struct Pe_ImportEntry_t Pe_ImportEntry_t;


#ifdef __cplusplus
}
#endif

/** @} */
#endif
