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
#include "Header.hpp"

namespace LIEF {
namespace ELF {

void init_c_header(Elf_Binary_t* c_binary, Binary* binary) {

  const Header& hdr                       = binary->header();
  c_binary->header.file_type              = static_cast<uint32_t>(hdr.file_type());
  c_binary->header.machine_type           = static_cast<uint32_t>(hdr.machine_type());
  c_binary->header.object_file_version    = static_cast<uint32_t>(hdr.object_file_version());
  c_binary->header.program_headers_offset = hdr.program_headers_offset();
  c_binary->header.section_headers_offset = hdr.section_headers_offset();
  c_binary->header.processor_flags        = hdr.processor_flag();
  c_binary->header.header_size            = hdr.header_size();
  c_binary->header.program_header_size    = hdr.program_header_size();
  c_binary->header.numberof_segments      = hdr.numberof_segments();
  c_binary->header.section_header_size    = hdr.section_header_size();
  c_binary->header.numberof_sections      = hdr.numberof_sections();
  c_binary->header.name_string_table_idx  = hdr.section_name_table_idx();
  c_binary->header.entrypoint             = hdr.entrypoint();
  const Header::identity_t& ident         = hdr.identity();
  std::copy(std::begin(ident), std::end(ident), c_binary->header.identity);

}

}
}
