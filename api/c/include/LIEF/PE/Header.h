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
#ifndef C_LIEF_PE_HEADER_H_
#define C_LIEF_PE_HEADER_H_

#include <inttypes.h>

#include "LIEF/PE/enums.h"
/**  @defgroup pe_header_c_api Header
 *  @ingroup pe_c_api
 *  @addtogroup pe_header_c_api
 *  @brief Header C API
 *
 *  @{
 */

#ifdef __cplusplus
extern "C" {
#endif

struct Pe_Header_t {
  uint8_t            signature[4];
  enum LIEF_PE_MACHINE_TYPES machine;
  uint16_t           numberof_sections;
  uint32_t           time_date_stamp;
  uint32_t           pointerto_symbol_table;
  uint32_t           numberof_symbols;
  uint16_t           sizeof_optional_header;
  uint16_t           characteristics;
};

typedef struct Pe_Header_t Pe_Header_t;


#ifdef __cplusplus
}
#endif

/** @} */
#endif
