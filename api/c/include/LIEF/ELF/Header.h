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
#ifndef LIEF_C_ELF_HEADER_H
#define LIEF_C_ELF_HEADER_H
#include <inttypes.h>

#include "LIEF/ELF/enums.h"

#ifdef __cplusplus
extern "C" {
#endif

struct Elf_Header_t {
  uint8_t  identity[LIEF_EI_NIDENT];
  uint32_t file_type;
  uint32_t machine_type;
  uint32_t object_file_version;
  uint64_t entrypoint;
  uint64_t program_headers_offset;
  uint64_t section_headers_offset;
  uint32_t processor_flags;
  uint32_t header_size;
  uint32_t program_header_size;
  uint32_t numberof_segments;
  uint32_t section_header_size;
  uint32_t numberof_sections;
  uint32_t name_string_table_idx;
};

typedef struct Elf_Header_t Elf_Header_t;


#ifdef __cplusplus
}
#endif

#endif
