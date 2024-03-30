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
#ifndef C_LIEF_PE_BINARY_H_
#define C_LIEF_PE_BINARY_H_

#include <stddef.h>

#include "LIEF/visibility.h"

#include "LIEF/PE/enums.h"

#include "LIEF/PE/DosHeader.h"
#include "LIEF/PE/Header.h"
#include "LIEF/PE/OptionalHeader.h"
#include "LIEF/PE/DataDirectory.h"
#include "LIEF/PE/Section.h"
#include "LIEF/PE/Import.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief LIEF::PE::Binary C Handler */
struct Pe_Binary_t {
  void*                handler;
  Pe_DosHeader_t       dos_header;
  Pe_Header_t          header;
  Pe_OptionalHeader_t  optional_header;
  Pe_DataDirectory_t** data_directories;
  Pe_Section_t**       sections;
  Pe_Import_t**        imports;
};

typedef struct Pe_Binary_t Pe_Binary_t;

/** Wrapper on LIEF::PE::Parser::parse */
LIEF_API Pe_Binary_t* pe_parse(const char *file);

LIEF_API void pe_binary_destroy(Pe_Binary_t* binary);

#ifdef __cplusplus
}
#endif

#endif
