/* Copyright 2024 R. Thomas
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
#pragma once
#include <cstdint>

#include "LIEF/PE/DosHeader.hpp"
#include "LIEF/rust/Mirror.hpp"

class PE_DosHeader : private Mirror<LIEF::PE::DosHeader> {
  public:
  using lief_t = LIEF::PE::DosHeader;
  using Mirror::Mirror;

  uint16_t magic() const { return get().magic(); }
  uint16_t used_bytes_in_last_page() const { return get().used_bytes_in_last_page(); }
  uint16_t file_size_in_pages() const { return get().file_size_in_pages(); }
  uint16_t numberof_relocation() const { return get().numberof_relocation(); }
  uint16_t header_size_in_paragraphs() const { return get().header_size_in_paragraphs(); }
  uint16_t minimum_extra_paragraphs() const { return get().minimum_extra_paragraphs(); }
  uint16_t maximum_extra_paragraphs() const { return get().maximum_extra_paragraphs(); }
  uint16_t initial_relative_ss() const { return get().initial_relative_ss(); }
  uint16_t initial_sp() const { return get().initial_sp(); }
  uint16_t checksum() const { return get().checksum(); }
  uint16_t initial_ip() const { return get().initial_ip(); }
  uint16_t initial_relative_cs() const { return get().initial_relative_cs(); }
  uint16_t addressof_relocation_table() const { return get().addressof_relocation_table(); }
  uint16_t overlay_number() const { return get().overlay_number(); }
  auto reserved() const {
    return details::make_vector(get().reserved());
  }

  uint16_t oem_id() const { return get().oem_id(); }
  uint16_t oem_info() const { return get().oem_info(); }

  auto reserved2() const {
    return details::make_vector(get().reserved2());
  }
  uint32_t addressof_new_exeheader() const { return get().addressof_new_exeheader(); }
};
