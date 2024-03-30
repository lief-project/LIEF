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
#ifndef LIEF_C_ELF_BINARY_H
#define LIEF_C_ELF_BINARY_H

#include <stddef.h>

#include "LIEF/visibility.h"

#include "LIEF/ELF/enums.h"

#include "LIEF/ELF/Section.h"
#include "LIEF/ELF/Segment.h"
#include "LIEF/ELF/Header.h"
#include "LIEF/ELF/DynamicEntry.h"
#include "LIEF/ELF/Symbol.h"

#ifdef __cplusplus
extern "C" {
#endif

/** LIEF::ELF::Binary C Handler */
struct Elf_Binary_t {
  void*              handler;
  const char*        interpreter;
  uint32_t           type;
  Elf_Header_t       header;
  Elf_Section_t      **sections;
  Elf_Segment_t      **segments;
  Elf_DynamicEntry_t **dynamic_entries;
  Elf_Symbol_t       **dynamic_symbols;
  Elf_Symbol_t       **symtab_symbols;
};

typedef struct Elf_Binary_t Elf_Binary_t;

/** Wrapper for LIEF::ELF::Parser::parse */
LIEF_API Elf_Binary_t* elf_parse(const char *file);

LIEF_API void elf_binary_destroy(Elf_Binary_t* binary);

/** Update LIEF::ELF::Header object */
LIEF_API int elf_binary_save_header(Elf_Binary_t* binary);

#ifdef __cplusplus
}
#endif

#endif
