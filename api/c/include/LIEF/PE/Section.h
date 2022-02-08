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
#ifndef C_LIEF_PE_SECTION_H_
#define C_LIEF_PE_SECTION_H_

#include <inttypes.h>

#include "LIEF/PE/enums.h"
/**  @defgroup pe_section_c_api Section
 *  @ingroup pe_c_api
 *  @addtogroup pe_section_c_api
 *  @brief Section C API
 *
 *  @{
 */

#ifdef __cplusplus
extern "C" {
#endif

struct Pe_Section_t {
  const char* name;
  uint64_t    virtual_address;
  uint64_t    size;
  uint64_t    offset;

  uint32_t    virtual_size;
  uint32_t    pointerto_relocation;
  uint32_t    pointerto_line_numbers;
  uint32_t    characteristics;

  uint8_t*    content;
  uint64_t    content_size;
  double      entropy;

};

typedef struct Pe_Section_t Pe_Section_t;


#ifdef __cplusplus
}
#endif

/** @} */
#endif
