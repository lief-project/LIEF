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
#ifndef C_LIEF_MACHO_BINARY_H_
#define C_LIEF_MACHO_BINARY_H_

#include <stdint.h>

#include "LIEF/visibility.h"

#include "LIEF/MachO/Header.h"
#include "LIEF/MachO/LoadCommand.h"
#include "LIEF/MachO/Symbol.h"
#include "LIEF/MachO/Section.h"
#include "LIEF/MachO/Segment.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief LIEF::MachO::Binary C Handler */
struct Macho_Binary_t {
  void*               handler;
  uint64_t            imagebase;
  Macho_Header_t      header;
  Macho_Command_t**   commands;
  Macho_Symbol_t**    symbols;
  Macho_Section_t**   sections;
  Macho_Segment_t**   segments;

};

typedef struct Macho_Binary_t Macho_Binary_t;

/** @brief Wrapper on LIEF::MachO::Parser::parse */
LIEF_API Macho_Binary_t** macho_parse(const char *file);

LIEF_API void macho_binaries_destroy(Macho_Binary_t** binaries);

#ifdef __cplusplus
}
#endif


#endif
