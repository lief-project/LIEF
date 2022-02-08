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
#ifndef C_LIEF_MACHO_SYMBOL_H_
#define C_LIEF_MACHO_SYMBOL_H_
#include <inttypes.h>

#include "LIEF/MachO/enums.h"
/**  @defgroup macho_symbol_c_api Header
 *  @ingroup macho_c_api
 *  @addtogroup macho_symbol_c_api
 *  @brief Symbol C API
 *
 *  @{
 */

#ifdef __cplusplus
extern "C" {
#endif

struct Macho_Symbol_t {
  const char* name;
  uint8_t     type;
  uint8_t     numberof_sections;
  uint16_t    description;
  uint64_t    value;
};

typedef struct Macho_Symbol_t Macho_Symbol_t;


#ifdef __cplusplus
}
#endif

/** @} */
#endif
