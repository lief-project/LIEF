/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#ifndef LIEF_C_ELF_UTILS_H
#define LIEF_C_ELF_UTILS_H

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


#endif
