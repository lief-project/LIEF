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
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV9.hpp"
#include "LIEF/rust/PE/LoadConfiguration/LoadConfigurationV8.hpp"

class PE_LoadConfigurationV9 : public PE_LoadConfigurationV8 {
  using lief_t = LIEF::PE::LoadConfigurationV9;
  public:
  PE_LoadConfigurationV9(const lief_t& base) : PE_LoadConfigurationV8(base) {}

  static bool classof(const PE_LoadConfiguration& config) {
    return lief_t::classof(&config.get());
  }

  uint64_t guard_eh_continuation_table() const { return impl().guard_eh_continuation_table(); }
  uint64_t guard_eh_continuation_count() const { return impl().guard_eh_continuation_count(); }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
