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
#ifndef C_LIEF_PE_IMPORT_H_
#define C_LIEF_PE_IMPORT_H_

#include <inttypes.h>

#include "LIEF/PE/enums.h"
#include "LIEF/PE/ImportEntry.h"

/**  @defgroup pe_import_c_api Import
 *  @ingroup pe_c_api
 *  @addtogroup pe_import_c_api
 *  @brief Import C API
 *
 *  @{
 */

#ifdef __cplusplus
extern "C" {
#endif

struct Pe_Import_t {
  const char*        name;
  uint32_t           forwarder_chain;
  uint32_t           timedatestamp;
  Pe_ImportEntry_t** entries;
  uint32_t           import_address_table_rva;
  uint32_t           import_lookup_table_rva;
};

typedef struct Pe_Import_t Pe_Import_t;


#ifdef __cplusplus
}
#endif

/** @} */
#endif
