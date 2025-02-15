/* Copyright 2024 - 2025 R. Thomas
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

  auto major_linker_version() const { return get().major_linker_version(); }
  auto minor_linker_version() const { return get().minor_linker_version(); }
  auto sizeof_code() const { return get().sizeof_code(); }
  auto sizeof_initialized_data() const { return get().sizeof_initialized_data(); }
  auto sizeof_uninitialized_data() const { return get().sizeof_uninitialized_data(); }
  auto addressof_entrypoint() const { return get().addressof_entrypoint(); }
  auto baseof_code() const { return get().baseof_code(); }
  auto baseof_data() const { return get().baseof_data(); }
  auto imagebase() const { return get().imagebase(); }
  auto section_alignment() const { return get().section_alignment(); }
  auto file_alignment() const { return get().file_alignment(); }
  auto major_operating_system_version() const { return get().major_operating_system_version(); }
  auto minor_operating_system_version() const { return get().minor_operating_system_version(); }
  auto major_image_version() const { return get().major_image_version(); }
  auto minor_image_version() const { return get().minor_image_version(); }
  auto major_subsystem_version() const { return get().major_subsystem_version(); }
  auto minor_subsystem_version() const { return get().minor_subsystem_version(); }
  auto win32_version_value() const { return get().win32_version_value(); }
  auto sizeof_image() const { return get().sizeof_image(); }
  auto sizeof_headers() const { return get().sizeof_headers(); }
  auto checksum() const { return get().checksum(); }
  auto subsystem() const { return to_int(get().subsystem()); }
  auto dll_characteristics() const { return get().dll_characteristics(); }
  auto sizeof_stack_reserve() const { return get().sizeof_stack_reserve(); }
  auto sizeof_stack_commit() const { return get().sizeof_stack_commit(); }
  auto sizeof_heap_reserve() const { return get().sizeof_heap_reserve(); }
  auto sizeof_heap_commit() const { return get().sizeof_heap_commit(); }
  auto loader_flags() const { return get().loader_flags(); }
  auto numberof_rva_and_size() const { return get().numberof_rva_and_size(); }

  void set_addressof_entrypoint(uint32_t value) {
    get().addressof_entrypoint(value);
  }

  void set_imagebase(uint64_t value) {
    get().imagebase(value);
  }
};
