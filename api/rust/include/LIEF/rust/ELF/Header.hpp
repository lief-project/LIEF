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
#include <LIEF/ELF/Header.hpp>
#include <LIEF/rust/Mirror.hpp>
#include <LIEF/rust/helpers.hpp>

class ELF_Header : public Mirror<LIEF::ELF::Header> {
  public:
  using Mirror::Mirror;

  uint64_t entrypoint() const { return get().entrypoint(); }
  auto file_type() const { return to_int(get().file_type()); }
  auto machine_type() const { return to_int(get().machine_type()); }
  auto object_file_version() const { return to_int(get().object_file_version()); }
  auto identity_class() const { return to_int(get().identity_class()); }
  auto identity_os_abi() const { return to_int(get().identity_os_abi()); }
  auto identity_version() const { return to_int(get().identity_version()); }
  auto identity_data() const { return to_int(get().identity_data()); }
  uint32_t identity_abi_version() const { return get().identity_abi_version(); }
  uint64_t program_headers_offset() const { return get().program_headers_offset(); }
  uint64_t section_headers_offset() const { return get().section_headers_offset(); }
  uint32_t processor_flag() const { return get().processor_flag(); }
  uint32_t header_size() const { return get().header_size(); }
  uint32_t program_header_size() const { return get().program_header_size(); }
  uint32_t numberof_segments() const { return get().numberof_segments(); }
  uint32_t section_header_size() const { return get().section_header_size(); }
  uint32_t numberof_sections() const { return get().numberof_sections(); }
  uint32_t section_name_table_idx() const { return get().section_name_table_idx(); }
};
