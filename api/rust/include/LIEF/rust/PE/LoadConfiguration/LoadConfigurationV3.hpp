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
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV3.hpp"
#include "LIEF/rust/PE/LoadConfiguration/LoadConfigurationV2.hpp"

class PE_LoadConfigurationV3 : public PE_LoadConfigurationV2 {
  public:
  using lief_t = LIEF::PE::LoadConfigurationV3;
  PE_LoadConfigurationV3(const lief_t& base) : PE_LoadConfigurationV2(base) {}

  uint64_t guard_address_taken_iat_entry_table() const { return impl().guard_address_taken_iat_entry_table(); }
  uint64_t guard_address_taken_iat_entry_count() const { return impl().guard_address_taken_iat_entry_count(); }
  uint64_t guard_long_jump_target_table() const { return impl().guard_long_jump_target_table(); }
  uint64_t guard_long_jump_target_count() const { return impl().guard_long_jump_target_count(); }

  static bool classof(const PE_LoadConfiguration& config) {
    return lief_t::classof(&config.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
