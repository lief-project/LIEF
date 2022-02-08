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
#ifndef C_LIEF_MACHO_HEADER_H_
#define C_LIEF_MACHO_HEADER_H_
#include <inttypes.h>

#include "LIEF/MachO/enums.h"
/**  @defgroup macho_header_c_api Header
 *  @ingroup macho_c_api
 *  @addtogroup macho_header_c_api
 *  @brief Header C API
 *
 *  @{
 */

#ifdef __cplusplus
extern "C" {
#endif

struct Macho_Header_t {
  uint32_t        magic;
  enum LIEF_MACHO_CPU_TYPES  cpu_type;
  uint32_t        cpu_subtype;
  enum LIEF_MACHO_FILE_TYPES file_type;
  uint32_t        nb_cmds;
  uint32_t        sizeof_cmds;
  uint32_t        flags;
  uint32_t        reserved;
};

typedef struct Macho_Header_t Macho_Header_t;


#ifdef __cplusplus
}
#endif

/** @} */
#endif
