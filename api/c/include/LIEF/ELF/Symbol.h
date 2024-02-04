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
#ifndef LIEF_C_ELF_SYMBOL_H
#define LIEF_C_ELF_SYMBOL_H

#include <stdint.h>
#include "LIEF/types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct Elf_Symbol_t {
  const char* name;
  uint32_t    type;
  uint32_t    binding;
  uint8_t     information;
  uint8_t     other;
  uint16_t    shndx;
  uint64_t    value;
  uint64_t    size;
  bool        is_exported; /**< Whether or not the symbol is exported */
  bool        is_imported; /**< Whether or not the symbol is imported */
};

typedef struct Elf_Symbol_t Elf_Symbol_t;

#ifdef __cplusplus
}
#endif

#endif
