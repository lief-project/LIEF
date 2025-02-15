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
#include "LIEF/PE/LoadConfigurations/LoadConfiguration.hpp"
#include "LIEF/rust/PE/CodeIntegrity.hpp"
#include "LIEF/rust/PE/LoadConfiguration/CHPEMetadata.hpp"
#include "LIEF/rust/PE/LoadConfiguration/EnclaveConfiguration.hpp"
#include "LIEF/rust/PE/LoadConfiguration/VolatileMetadata.hpp"
#include "LIEF/rust/PE/LoadConfiguration/DynamicRelocation/DynamicRelocation.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/optional.hpp"

class PE_LoadConfiguration_guard_function_t : public Mirror<LIEF::PE::LoadConfiguration::guard_function_t> {
  public:
  using lief_t = LIEF::PE::LoadConfiguration::guard_function_t;
  using Mirror::Mirror;

  auto rva() const { return get().rva; }
  auto extra() const { return get().extra; }

};

class PE_LoadConfiguration : public Mirror<LIEF::PE::LoadConfiguration> {
  public:
  using lief_t = LIEF::PE::LoadConfiguration;
  using Mirror::Mirror;

  class it_guard_cf_functions :
      public Iterator<PE_LoadConfiguration_guard_function_t, LIEF::PE::LoadConfiguration::it_const_guard_functions>
  {
    public:
    it_guard_cf_functions(const PE_LoadConfiguration::lief_t& src)
      : Iterator(std::move(src.guard_cf_functions())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_guard_address_taken_iat_entries :
      public Iterator<PE_LoadConfiguration_guard_function_t, LIEF::PE::LoadConfiguration::it_const_guard_functions>
  {
    public:
    it_guard_address_taken_iat_entries(const PE_LoadConfiguration::lief_t& src)
      : Iterator(std::move(src.guard_address_taken_iat_entries())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_guard_long_jump_targets :
      public Iterator<PE_LoadConfiguration_guard_function_t, LIEF::PE::LoadConfiguration::it_const_guard_functions>
  {
    public:
    it_guard_long_jump_targets(const PE_LoadConfiguration::lief_t& src)
      : Iterator(std::move(src.guard_long_jump_targets())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_guard_eh_continuation :
      public Iterator<PE_LoadConfiguration_guard_function_t, LIEF::PE::LoadConfiguration::it_const_guard_functions>
  {
    public:
    it_guard_eh_continuation(const PE_LoadConfiguration::lief_t& src)
      : Iterator(std::move(src.guard_eh_continuation_functions())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_dynamic_relocations :
      public Iterator<PE_DynamicRelocation, LIEF::PE::LoadConfiguration::it_const_dynamic_relocations_t>
  {
    public:
    it_dynamic_relocations(const PE_LoadConfiguration::lief_t& src)
      : Iterator(std::move(src.dynamic_relocations())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  auto characteristics() const { return get().characteristics(); }
  auto size() const { return get().size(); }
  auto timedatestamp() const { return get().timedatestamp(); }
  auto major_version() const { return get().major_version(); }
  auto minor_version() const { return get().minor_version(); }
  auto global_flags_clear() const { return get().global_flags_clear(); }
  auto global_flags_set() const { return get().global_flags_set(); }
  auto critical_section_default_timeout() const { return get().critical_section_default_timeout(); }
  auto decommit_free_block_threshold() const { return get().decommit_free_block_threshold(); }
  auto decommit_total_free_threshold() const { return get().decommit_total_free_threshold(); }
  auto lock_prefix_table() const { return get().lock_prefix_table(); }
  auto maximum_allocation_size() const { return get().maximum_allocation_size(); }
  auto virtual_memory_threshold() const { return get().virtual_memory_threshold(); }
  auto process_affinity_mask() const { return get().process_affinity_mask(); }
  auto process_heap_flags() const { return get().process_heap_flags(); }
  auto csd_version() const { return get().csd_version(); }
  auto reserved1() const { return get().reserved1(); }
  auto dependent_load_flags() const { return get().dependent_load_flags(); }
  auto editlist() const { return get().editlist(); }
  auto security_cookie() const { return get().security_cookie(); }

  uint64_t se_handler_table(uint32_t& is_set) const {
    return details::make_optional(get().se_handler_table(), is_set);
  }

  uint64_t se_handler_count(uint32_t& is_set) const {
    return details::make_optional(get().se_handler_count(), is_set);
  }

  auto seh_functions() const { return get().seh_functions(); }

  uint64_t guard_cf_check_function_pointer(uint32_t& is_set) const {
    return details::make_optional(get().guard_cf_check_function_pointer(), is_set);
  }

  uint64_t guard_cf_dispatch_function_pointer(uint32_t& is_set) const {
    return details::make_optional(get().guard_cf_dispatch_function_pointer(), is_set);
  }

  uint64_t guard_cf_function_table(uint32_t& is_set) const {
    return details::make_optional(get().guard_cf_function_table(), is_set);
  }

  uint64_t guard_cf_function_count(uint32_t& is_set) const {
    return details::make_optional(get().guard_cf_function_count(), is_set);
  }

  auto guard_cf_functions() const {
    return std::make_unique<it_guard_cf_functions>(get());
  }

  auto guard_flags(uint32_t& is_set) const {
    return details::make_optional(get().guard_flags(), is_set);
  }

  auto code_integrity() const {
    return details::try_unique<PE_CodeIntegrity>(get().code_integrity());
  }

  uint64_t guard_address_taken_iat_entry_table(uint32_t& is_set) const {
    return details::make_optional(get().guard_address_taken_iat_entry_table(), is_set);
  }

  uint64_t guard_address_taken_iat_entry_count(uint32_t& is_set) const {
    return details::make_optional(get().guard_address_taken_iat_entry_count(), is_set);
  }

  auto guard_address_taken_iat_entries() const {
    return std::make_unique<it_guard_address_taken_iat_entries>(get());
  }

  uint64_t guard_long_jump_target_table(uint32_t& is_set) const {
    return details::make_optional(get().guard_long_jump_target_table(), is_set);
  }

  uint64_t guard_long_jump_target_count(uint32_t& is_set) const {
    return details::make_optional(get().guard_long_jump_target_count(), is_set);
  }

  auto guard_long_jump_targets() const {
    return std::make_unique<it_guard_long_jump_targets>(get());
  }

  uint64_t dynamic_value_reloc_table(uint32_t& is_set) const {
    return details::make_optional(get().dynamic_value_reloc_table(), is_set);
  }

  uint64_t hybrid_metadata_pointer(uint32_t& is_set) const {
    return details::make_optional(get().hybrid_metadata_pointer(), is_set);
  }

  uint64_t chpe_metadata_pointer(uint32_t& is_set) const {
    return details::make_optional(get().chpe_metadata_pointer(), is_set);
  }

  auto chpe_metadata() const {
    return details::try_unique<PE_CHPEMetadata>(get().chpe_metadata());
  }

  uint64_t guard_rf_failure_routine(uint32_t& is_set) const {
    return details::make_optional(get().guard_rf_failure_routine(), is_set);
  }

  uint64_t guard_rf_failure_routine_function_pointer(uint32_t& is_set) const {
    return details::make_optional(get().guard_rf_failure_routine_function_pointer(), is_set);
  }

  auto dynamic_value_reloctable_offset(uint32_t& is_set) const {
    return details::make_optional(get().dynamic_value_reloctable_offset(), is_set);
  }

  auto dynamic_value_reloctable_section(uint32_t& is_set) const {
    return details::make_optional(get().dynamic_value_reloctable_section(), is_set);
  }

  auto dynamic_relocations() const {
    return std::make_unique<it_dynamic_relocations>(get());
  }

  auto reserved2(uint32_t& is_set) const {
    return details::make_optional(get().reserved2(), is_set);
  }

  uint64_t guard_rf_verify_stackpointer_function_pointer(uint32_t& is_set) const {
    return details::make_optional(get().guard_rf_verify_stackpointer_function_pointer(), is_set);
  }

  auto hotpatch_table_offset(uint32_t& is_set) const {
    return details::make_optional(get().hotpatch_table_offset(), is_set);
  }

  auto reserved3(uint32_t& is_set) const {
    return details::make_optional(get().reserved3(), is_set);
  }

  uint64_t enclave_configuration_ptr(uint32_t& is_set) const {
    return details::make_optional(get().enclave_configuration_ptr(), is_set);
  }

  auto enclave_config() const {
    return details::try_unique<PE_EnclaveConfiguration>(get().enclave_config());
  }

  uint64_t volatile_metadata_pointer(uint32_t& is_set) const {
    return details::make_optional(get().volatile_metadata_pointer(), is_set);
  }

  auto volatile_metadata() const {
    return details::try_unique<PE_VolatileMetadata>(get().volatile_metadata());
  }

  uint64_t guard_eh_continuation_table(uint32_t& is_set) const {
    return details::make_optional(get().guard_eh_continuation_table(), is_set);
  }

  uint64_t guard_eh_continuation_count(uint32_t& is_set) const {
    return details::make_optional(get().guard_eh_continuation_count(), is_set);
  }

  auto guard_eh_continuation_functions() const {
    return std::make_unique<it_guard_eh_continuation>(get());
  }

  uint64_t guard_xfg_check_function_pointer(uint32_t& is_set) const {
    return details::make_optional(get().guard_xfg_check_function_pointer(), is_set);
  }

  uint64_t guard_xfg_dispatch_function_pointer(uint32_t& is_set) const {
    return details::make_optional(get().guard_xfg_dispatch_function_pointer(), is_set);
  }

  uint64_t guard_xfg_table_dispatch_function_pointer(uint32_t& is_set) const {
    return details::make_optional(get().guard_xfg_table_dispatch_function_pointer(), is_set);
  }

  uint64_t cast_guard_os_determined_failure_mode(uint32_t& is_set) const {
    return details::make_optional(get().cast_guard_os_determined_failure_mode(), is_set);
  }

  uint64_t guard_memcpy_function_pointer(uint32_t& is_set) const {
    return details::make_optional(get().guard_memcpy_function_pointer(), is_set);
  }

  void set_characteristics(uint32_t characteristics) {
    get().characteristics(characteristics);
  }

  void set_size(uint32_t value) {
    get().size(value);
  }

  void set_timedatestamp(uint32_t timedatestamp) {
    get().timedatestamp(timedatestamp);
  }

  void set_major_version(uint16_t major_version) {
    get().major_version(major_version);
  }

  void set_minor_version(uint16_t minor_version) {
    get().minor_version(minor_version);
  }

  void set_global_flags_clear(uint32_t global_flags_clear) {
    get().global_flags_clear(global_flags_clear);
  }

  void set_global_flags_set(uint32_t global_flags_set) {
    get().global_flags_set(global_flags_set);
  }

  void set_critical_section_default_timeout(uint32_t val) {
    get().critical_section_default_timeout(val);
  }

  void set_decommit_free_block_threshold(uint64_t val) {
    get().decommit_free_block_threshold(val);
  }

  void set_decommit_total_free_threshold(uint64_t val) {
    get().decommit_total_free_threshold(val);
  }

  void set_lock_prefix_table(uint64_t val) {
    get().lock_prefix_table(val);
  }

  void set_maximum_allocation_size(uint64_t val) {
    get().maximum_allocation_size(val);
  }

  void set_virtual_memory_threshold(uint64_t val) {
    get().virtual_memory_threshold(val);
  }

  void set_process_affinity_mask(uint64_t val) {
    get().process_affinity_mask(val);
  }

  void set_process_heap_flags(uint32_t val) {
    get().process_heap_flags(val);
  }

  void set_csd_version(uint16_t val) {
    get().csd_version(val);
  }

  void set_reserved1(uint16_t val) {
    get().reserved1(val);
  }

  void set_dependent_load_flags(uint16_t val) {
    get().dependent_load_flags(val);
  }

  void set_editlist(uint32_t val) {
    get().editlist(val);
  }

  void set_security_cookie(uint64_t val) {
    get().security_cookie(val);
  }

  void set_se_handler_table(uint64_t val) {
    get().se_handler_table(val);
  }

  void set_se_handler_count(uint64_t val) {
    get().se_handler_count(val);
  }

  void set_guard_cf_check_function_pointer(uint64_t val) {
    get().guard_cf_check_function_pointer(val);
  }

  void set_guard_cf_dispatch_function_pointer(uint64_t val) {
    get().guard_cf_dispatch_function_pointer(val);
  }

  void set_guard_cf_function_table(uint64_t val) {
    get().guard_cf_function_table(val);
  }

  void set_guard_cf_function_count(uint64_t val) {
    get().guard_cf_function_count(val);
  }

  void set_guard_flags(uint32_t flags) {
    get().guard_flags(flags);
  }

  void set_guard_address_taken_iat_entry_table(uint64_t value) {
    get().guard_address_taken_iat_entry_table(value);
  }

  void set_guard_address_taken_iat_entry_count(uint64_t value) {
    get().guard_address_taken_iat_entry_count(value);
  }

  void set_guard_long_jump_target_table(uint64_t value) {
    get().guard_long_jump_target_table(value);
  }

  void set_guard_long_jump_target_count(uint64_t value) {
    get().guard_long_jump_target_count(value);
  }

  void set_dynamic_value_reloc_table(uint64_t value) {
    get().dynamic_value_reloc_table(value);
  }

  void set_hybrid_metadata_pointer(uint64_t value) {
    get().hybrid_metadata_pointer(value);
  }

  void set_guard_rf_failure_routine(uint64_t value) {
    get().guard_rf_failure_routine(value);
  }

  void set_guard_rf_failure_routine_function_pointer(uint64_t value) {
    get().guard_rf_failure_routine_function_pointer(value);
  }

  void set_dynamic_value_reloctable_offset(uint32_t value) {
    get().dynamic_value_reloctable_offset(value);
  }

  void set_dynamic_value_reloctable_section(uint16_t value) {
    get().dynamic_value_reloctable_section(value);
  }

  void set_reserved2(uint16_t value) {
    get().reserved2(value);
  }

  void set_guard_rf_verify_stackpointer_function_pointer(uint64_t value) {
    get().guard_rf_verify_stackpointer_function_pointer(value);
  }

  void set_hotpatch_table_offset(uint32_t value) {
    get().hotpatch_table_offset(value);
  }

  void set_reserved3(uint32_t value) {
    get().reserved3(value);
  }

  void set_enclave_configuration_ptr(uint64_t value) {
    get().enclave_configuration_ptr(value);
  }

  void set_volatile_metadata_pointer(uint64_t value) {
    get().volatile_metadata_pointer(value);
  }

  void set_guard_eh_continuation_table(uint64_t value) {
    get().guard_eh_continuation_table(value);
  }

  void set_guard_eh_continuation_count(uint64_t value) {
    get().guard_eh_continuation_count(value);
  }

  void set_guard_xfg_check_function_pointer(uint64_t value) {
    get().guard_xfg_check_function_pointer(value);
  }

  void set_guard_xfg_dispatch_function_pointer(uint64_t value) {
    get().guard_xfg_dispatch_function_pointer(value);
  }

  void set_guard_xfg_table_dispatch_function_pointer(uint64_t value) {
    get().guard_xfg_table_dispatch_function_pointer(value);
  }

  void set_cast_guard_os_determined_failure_mode(uint64_t value) {
    get().cast_guard_os_determined_failure_mode(value);
  }

  void set_guard_memcpy_function_pointer(uint64_t value) {
    get().guard_memcpy_function_pointer(value);
  }
};
