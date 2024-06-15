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

#include "LIEF/PE/OptionalHeader.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"

class PE_OptionalHeader : private Mirror<LIEF::PE::OptionalHeader>  {
  public:
  using lief_t = LIEF::PE::OptionalHeader;
  using Mirror::Mirror;

  uint8_t major_linker_version() const { return get().major_linker_version(); }
  uint8_t minor_linker_version() const { return get().minor_linker_version(); }
  uint32_t sizeof_code() const { return get().sizeof_code(); }
  uint32_t sizeof_initialized_data() const { return get().sizeof_initialized_data(); }
  uint32_t sizeof_uninitialized_data() const { return get().sizeof_uninitialized_data(); }
  uint32_t addressof_entrypoint() const { return get().addressof_entrypoint(); }
  uint32_t baseof_code() const { return get().baseof_code(); }
  uint32_t baseof_data() const { return get().baseof_data(); }
  uint64_t imagebase() const { return get().imagebase(); }
  uint32_t section_alignment() const { return get().section_alignment(); }
  uint32_t file_alignment() const { return get().file_alignment(); }
  uint32_t major_operating_system_version() const { return get().major_operating_system_version(); }
  uint32_t minor_operating_system_version() const { return get().minor_operating_system_version(); }
  uint32_t major_image_version() const { return get().major_image_version(); }
  uint32_t minor_image_version() const { return get().minor_image_version(); }
  uint32_t major_subsystem_version() const { return get().major_subsystem_version(); }
  uint32_t minor_subsystem_version() const { return get().minor_subsystem_version(); }
  uint32_t win32_version_value() const { return get().win32_version_value(); }
  uint32_t sizeof_image() const { return get().sizeof_image(); }
  uint32_t sizeof_headers() const { return get().sizeof_headers(); }
  uint32_t checksum() const { return get().checksum(); }
  auto subsystem() const { return to_int(get().subsystem()); }
  auto dll_characteristics() const { return get().dll_characteristics(); }
  uint64_t sizeof_stack_reserve() const { return get().sizeof_stack_reserve(); }
  uint64_t sizeof_stack_commit() const { return get().sizeof_stack_commit(); }
  uint64_t sizeof_heap_reserve() const { return get().sizeof_heap_reserve(); }
  uint64_t sizeof_heap_commit() const { return get().sizeof_heap_commit(); }
  uint32_t loader_flags() const { return get().loader_flags(); }
  uint32_t numberof_rva_and_size() const { return get().numberof_rva_and_size(); }
};
