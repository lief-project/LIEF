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
#ifndef C_LIEF_ELF_SEGMENT_H_
#define C_LIEF_ELF_SEGMENT_H_

#include <stdint.h>

#include "LIEF/ELF/enums.h"

/**  @defgroup elf_segment_c_api Segment
 *  @ingroup elf_c_api
 *  @addtogroup elf_segment_c_api
 *  @brief Segment C API
 *
 *  @{
 */

#ifdef __cplusplus
extern "C" {
#endif

struct Elf_Segment_t {
  enum LIEF_ELF_SEGMENT_TYPES type;
  uint32_t flags;
  uint64_t virtual_address;
  uint64_t virtual_size;
  uint64_t offset;
  uint64_t alignment;
  uint64_t size;
  uint8_t* content;
};

typedef struct Elf_Segment_t Elf_Segment_t;

#ifdef __cplusplus
}
#endif

/** @} */
#endif
