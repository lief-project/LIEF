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
#ifndef C_LIEF_ELF_UTILS_H_
#define C_LIEF_ELF_UTILS_H_

/** @defgroup elf_utils_c_api Utils
 *  @ingroup elf_c_api
 *  @addtogroup elf_utils_c_api
 *  @brief Utils C API
 *
 *  @{
 */

#include <stddef.h>

#include "LIEF/visibility.h"
#include "LIEF/types.h"


#ifdef __cplusplus
extern "C" {
#endif

/** @brief Check if the given file is an ELF one. */
LIEF_API bool is_elf(const char* file);

#ifdef __cplusplus
}
#endif


/** @} */
#endif
