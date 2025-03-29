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
#include "LIEF/rust/ELF/DynamicEntry.hpp"
#include "LIEF/ELF/DynamicEntryFlags.hpp"

class ELF_DynamicEntryFlags : public ELF_DynamicEntry {
  public:
  using lief_t = LIEF::ELF::DynamicEntryFlags;

  auto flags() const {
    return impl().raw_flags();
  }

  static bool classof(const ELF_DynamicEntry& entry) {
    return lief_t::classof(&entry.get());
  }

  static auto create_dt_flag(uint64_t value) {
    return LIEF::ELF::DynamicEntryFlags::create_dt_flag(value).clone();
  }

  static auto create_dt_flag_1(uint64_t value) {
    return LIEF::ELF::DynamicEntryFlags::create_dt_flag_1(value).clone();
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
