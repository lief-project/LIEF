/* Copyright 2022 - 2026 R. Thomas
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

#include "LIEF/rust/Iterator.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"
#include "LIEF/rust/optional.hpp"

#include "LIEF/runtime/windows/LdrDataTableEntry.hpp"

class runtime_windows_LdrDataTableEntry
  : public Mirror<LIEF::runtime::windows::LdrDataTableEntry> {
  public:
  using lief_t = LIEF::runtime::windows::LdrDataTableEntry;
  using Mirror::Mirror;

  auto dll_base() const {
    return (uint64_t)get().dll_base();
  }

  auto entry_point() const {
    return (uint64_t)get().entry_point();
  }

  auto size_of_image() const {
    return get().size_of_image();
  }

  auto full_dll_name() const {
    return to_unique_string(get().full_dll_name());
  }

  auto base_dll_name() const {
    return to_unique_string(get().base_dll_name());
  }

  auto flags() const {
    return get().flags();
  }

  auto obsolete_load_count() const {
    return get().obsolete_load_count();
  }

  auto tls_index() const {
    return get().tls_index();
  }

  auto time_date_stamp() const {
    return get().time_date_stamp();
  }

  auto entry_point_activation_context() const {
    return (uint64_t)get().entry_point_activation_context();
  }

  auto lock() const {
    return (uint64_t)get().lock();
  }

  uint64_t ddag_node(uint32_t& is_set) const {
    return details::make_optional(get().ddag_node(), is_set);
  }

  uint64_t load_context(uint32_t& is_set) const {
    return details::make_optional(get().load_context(), is_set);
  }

  uint64_t parent_dll_base(uint32_t& is_set) const {
    return details::make_optional(get().parent_dll_base(), is_set);
  }

  uint64_t switch_back_context(uint32_t& is_set) const {
    return details::make_optional(get().switch_back_context(), is_set);
  }

  uint64_t original_base(uint32_t& is_set) const {
    return details::make_optional(get().original_base(), is_set);
  }

  int64_t load_time(uint32_t& is_set) const {
    return details::make_optional(get().load_time(), is_set);
  }

  uint32_t base_name_hash_value(uint32_t& is_set) const {
    return details::make_optional(get().base_name_hash_value(), is_set);
  }

  int32_t load_reason(uint32_t& is_set) const {
    return details::make_optional(get().load_reason(), is_set);
  }

  uint32_t implicit_path_options(uint32_t& is_set) const {
    return details::make_optional(get().implicit_path_options(), is_set);
  }

  uint32_t reference_count(uint32_t& is_set) const {
    return details::make_optional(get().reference_count(), is_set);
  }

  uint32_t dependent_load_flags(uint32_t& is_set) const {
    return details::make_optional(get().dependent_load_flags(), is_set);
  }

  uint8_t signing_level(uint32_t& is_set) const {
    return details::make_optional(get().signing_level(), is_set);
  }

  uint32_t check_sum(uint32_t& is_set) const {
    return details::make_optional(get().check_sum(), is_set);
  }

  uint64_t active_patch_image_base(uint32_t& is_set) const {
    return details::make_optional(get().active_patch_image_base(), is_set);
  }

  uint32_t hot_patch_state(uint32_t& is_set) const {
    return details::make_optional(get().hot_patch_state(), is_set);
  }

  auto to_string() const {
    return to_unique_string(get().to_string());
  }
};

class runtime_windows_it_ldr_data_table_entry
  : public ForwardIterator<runtime_windows_LdrDataTableEntry,
                           LIEF::runtime::windows::LdrDataTableEntry::Iterator> {
  public:
  runtime_windows_it_ldr_data_table_entry(
      LIEF::iterator_range<LIEF::runtime::windows::LdrDataTableEntry::Iterator>
          range
  ) :
    ForwardIterator(std::move(range)) {}

  // NOLINTNEXTLINE
  auto next() {
    return ForwardIterator::next();
  }
};
