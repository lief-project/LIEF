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
#ifndef LIEF_C_ELF_DYNAMIC_ENTRY_H
#define LIEF_C_ELF_DYNAMIC_ENTRY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct Elf_DynamicEntry_t {
  uint64_t tag;
  uint64_t value;
};

struct Elf_DynamicEntry_Library_t {
  uint64_t    tag;
  uint64_t    value;
  const char* name;
};

struct Elf_DynamicEntry_SharedObject_t {
  uint64_t    tag;
  uint64_t    value;
  const char* name;
};

struct Elf_DynamicEntry_Array_t {
  uint64_t  tag;
  uint64_t  value;
  uint64_t* array;
};

struct Elf_DynamicEntry_Rpath_t {
  uint64_t    tag;
  uint64_t    value;
  const char* rpath;
};

struct Elf_DynamicEntry_RunPath_t {
  uint64_t tag;
  uint64_t value;
  const char* runpath;
};

struct Elf_DynamicEntry_Flags_t {
  uint64_t tag;
  uint64_t value;
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

#endif
