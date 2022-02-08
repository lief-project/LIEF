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
#ifndef C_LIEF_PE_DOS_HEADER_H_
#define C_LIEF_PE_DOS_HEADER_H_
#include <inttypes.h>

#include "LIEF/ELF/enums.h"
/**  @defgroup pe_dos_header_c_api DosHeader
 *  @ingroup pe_c_api
 *  @addtogroup pe_dos_header_c_api
 *  @brief Dos Header C API
 *
 *  @{
 */

#ifdef __cplusplus
extern "C" {
#endif

struct Pe_DosHeader_t {
  uint16_t magic ;
  uint16_t used_bytes_in_the_last_page;
  uint16_t file_size_in_pages;
  uint16_t numberof_relocation;
  uint16_t header_size_in_paragraphs;
  uint16_t minimum_extra_paragraphs;
  uint16_t maximum_extra_paragraphs;
  uint16_t initial_relative_ss;
  uint16_t initial_sp;
  uint16_t checksum;
  uint16_t initial_ip;
  uint16_t initial_relative_cs;
  uint16_t addressof_relocation_table;
  uint16_t overlay_number;
  uint16_t reserved[4];
  uint16_t oem_id;
  uint16_t oem_info;
  uint16_t reserved2[10];
  uint32_t addressof_new_exeheader;
};

typedef struct Pe_DosHeader_t Pe_DosHeader_t;


#ifdef __cplusplus
}
#endif

/** @} */
#endif
