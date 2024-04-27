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
#include "LIEF/PE/LoadConfigurations/LoadConfiguration.hpp"
#include "LIEF/rust/Mirror.hpp"

class PE_LoadConfiguration : public Mirror<LIEF::PE::LoadConfiguration> {
  public:
  using lief_t = LIEF::PE::LoadConfiguration;
  using Mirror::Mirror;

  uint32_t characteristics() const { return get().characteristics(); }
  uint32_t size() const { return get().size(); }
  uint32_t timedatestamp() const { return get().timedatestamp(); }
  uint32_t major_version() const { return get().major_version(); }
  uint32_t minor_version() const { return get().minor_version(); }
  uint32_t global_flags_clear() const { return get().global_flags_clear(); }
  uint32_t global_flags_set() const { return get().global_flags_set(); }
  uint32_t critical_section_default_timeout() const { return get().critical_section_default_timeout(); }
  uint64_t decommit_free_block_threshold() const { return get().decommit_free_block_threshold(); }
  uint64_t decommit_total_free_threshold() const { return get().decommit_total_free_threshold(); }
  uint64_t lock_prefix_table() const { return get().lock_prefix_table(); }
  uint64_t maximum_allocation_size() const { return get().maximum_allocation_size(); }
  uint64_t virtual_memory_threshold() const { return get().virtual_memory_threshold(); }
  uint64_t process_affinity_mask() const { return get().process_affinity_mask(); }
  uint32_t process_heap_flags() const { return get().process_heap_flags(); }
  uint16_t csd_version() const { return get().csd_version(); }
  uint16_t reserved1() const { return get().reserved1(); }
  uint16_t dependent_load_flags() const { return get().dependent_load_flags(); }
  uint32_t editlist() const { return get().editlist(); }
  uint32_t security_cookie() const { return get().security_cookie(); }
};
