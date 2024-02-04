/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License",;
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
#ifndef C_LIEF_PE_DATA_DIRECTORY_H
#define C_LIEF_PE_DATA_DIRECTORY_H

#include <inttypes.h>

#include "LIEF/PE/enums.h"

#ifdef __cplusplus
extern "C" {
#endif


enum LIEF_PE_DATA_DIRECTORY {
  LIEF_PE_DATA_DIR_EXPORT_TABLE = 0,
  LIEF_PE_DATA_DIR_IMPORT_TABLE,
  LIEF_PE_DATA_DIR_RESOURCE_TABLE,
  LIEF_PE_DATA_DIR_EXCEPTION_TABLE,
  LIEF_PE_DATA_DIR_CERTIFICATE_TABLE,
  LIEF_PE_DATA_DIR_BASE_RELOCATION_TABLE,
  LIEF_PE_DATA_DIR_DEBUG,
  LIEF_PE_DATA_DIR_ARCHITECTURE,
  LIEF_PE_DATA_DIR_GLOBAL_PTR,
  LIEF_PE_DATA_DIR_TLS_TABLE,
  LIEF_PE_DATA_DIR_LOAD_CONFIG_TABLE,
  LIEF_PE_DATA_DIR_BOUND_IMPORT,
  LIEF_PE_DATA_DIR_IAT,
  LIEF_PE_DATA_DIR_DELAY_IMPORT_DESCRIPTOR,
  LIEF_PE_DATA_DIR_CLR_RUNTIME_HEADER,
  LIEF_PE_DATA_DIR_RESERVED,

  LIEF_PE_DATA_DIR_NONE,
};

struct Pe_DataDirectory_t {
  uint32_t rva;
  uint32_t size;
};

typedef struct Pe_DataDirectory_t Pe_DataDirectory_t;


#ifdef __cplusplus
}
#endif

#endif
