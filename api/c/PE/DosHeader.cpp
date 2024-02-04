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
#include "DosHeader.hpp"

namespace LIEF {
namespace PE {
void init_c_dos_header(Pe_Binary_t* c_binary, Binary* binary) {
  const DosHeader& dos_header                      = binary->dos_header();
  c_binary->dos_header.magic                       = dos_header.magic();
  c_binary->dos_header.used_bytes_in_last_page     = dos_header.used_bytes_in_last_page();
  c_binary->dos_header.file_size_in_pages          = dos_header.file_size_in_pages();
  c_binary->dos_header.numberof_relocation         = dos_header.numberof_relocation();
  c_binary->dos_header.header_size_in_paragraphs   = dos_header.header_size_in_paragraphs();
  c_binary->dos_header.minimum_extra_paragraphs    = dos_header.minimum_extra_paragraphs();
  c_binary->dos_header.maximum_extra_paragraphs    = dos_header.maximum_extra_paragraphs();
  c_binary->dos_header.initial_relative_ss         = dos_header.initial_relative_ss();
  c_binary->dos_header.initial_sp                  = dos_header.initial_sp();
  c_binary->dos_header.checksum                    = dos_header.checksum();
  c_binary->dos_header.initial_ip                  = dos_header.initial_ip();
  c_binary->dos_header.initial_relative_cs         = dos_header.initial_relative_cs();
  c_binary->dos_header.addressof_relocation_table  = dos_header.addressof_relocation_table();
  c_binary->dos_header.overlay_number              = dos_header.overlay_number();
  c_binary->dos_header.oem_id                      = dos_header.oem_id();
  c_binary->dos_header.oem_info                    = dos_header.oem_info();
  c_binary->dos_header.addressof_new_exeheader     = dos_header.addressof_new_exeheader();

  const DosHeader::reserved_t& reserved = dos_header.reserved();
  std::copy(
      std::begin(reserved),
      std::end(reserved),
      c_binary->dos_header.reserved);


  const DosHeader::reserved2_t& reserved2 = dos_header.reserved2();
  std::copy(
      std::begin(reserved2),
      std::end(reserved2),
      c_binary->dos_header.reserved2);
}

}
}
