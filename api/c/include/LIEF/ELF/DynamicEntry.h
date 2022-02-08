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
#ifndef C_LIEF_ELF_DYNAMIC_ENTRY_H_
#define C_LIEF_ELF_DYNAMIC_ENTRY_H_

#include <stdint.h>

#include "LIEF/ELF/enums.h"

/** @defgroup elf_dynamic_entry_c_api Dynamic Entry
 *  @ingroup elf_c_api
 *  @addtogroup elf_dynamic_entry_c_api
 *  @brief Dynamic Entry C API
 *
 *  @{
 */


#ifdef __cplusplus
extern "C" {
#endif

struct Elf_DynamicEntry_t {
  enum LIEF_ELF_DYNAMIC_TAGS tag;
  uint64_t          value;
};

struct Elf_DynamicEntry_Library_t {
  enum LIEF_ELF_DYNAMIC_TAGS tag;
  uint64_t          value;
  const char*       name;
};

struct Elf_DynamicEntry_SharedObject_t {
  enum LIEF_ELF_DYNAMIC_TAGS tag;
  uint64_t          value;
  const char*       name;
};

struct Elf_DynamicEntry_Array_t {
  enum LIEF_ELF_DYNAMIC_TAGS tag;
  uint64_t          value;
  uint64_t*         array;
};

struct Elf_DynamicEntry_Rpath_t {
  enum LIEF_ELF_DYNAMIC_TAGS tag;
  uint64_t          value;
  const char*       rpath;
};

struct Elf_DynamicEntry_RunPath_t {
  enum LIEF_ELF_DYNAMIC_TAGS tag;
  uint64_t          value;
  const char*       runpath;
};


struct Elf_DynamicEntry_Flags_t {
  enum LIEF_ELF_DYNAMIC_TAGS    tag;
  uint64_t             value;
  enum LIEF_ELF_DYNAMIC_FLAGS   *flags;
  enum LIEF_ELF_DYNAMIC_FLAGS_1 *flags_1;
};

typedef struct Elf_DynamicEntry_t              Elf_DynamicEntry_t;
typedef struct Elf_DynamicEntry_Library_t      Elf_DynamicEntry_Library_t;
typedef struct Elf_DynamicEntry_SharedObject_t Elf_DynamicEntry_SharedObject_t;
typedef struct Elf_DynamicEntry_Array_t        Elf_DynamicEntry_Array_t;
typedef struct Elf_DynamicEntry_Rpath_t        Elf_DynamicEntry_Rpath_t;
typedef struct Elf_DynamicEntry_RunPath_t      Elf_DynamicEntry_RunPath_t;
typedef struct Elf_DynamicEntry_Flags_t        Elf_DynamicEntry_Flags_t;

#ifdef __cplusplus
}
#endif

/** @} */
#endif
