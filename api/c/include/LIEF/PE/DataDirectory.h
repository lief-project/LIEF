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
#ifndef C_LIEF_PE_DATA_DIRECTORY_H_
#define C_LIEF_PE_DATA_DIRECTORY_H_

#include <inttypes.h>

#include "LIEF/PE/enums.h"
/**  @defgroup pe_data_directory_c_api Section
 *  @ingroup pe_c_api
 *  @addtogroup pe_data_directory_c_api
 *  @brief Data directory C API
 *
 *  @{
 */

#ifdef __cplusplus
extern "C" {
#endif

struct Pe_DataDirectory_t {
  uint32_t rva;
  uint32_t size;
};

typedef struct Pe_DataDirectory_t Pe_DataDirectory_t;


#ifdef __cplusplus
}
#endif

/** @} */
#endif
