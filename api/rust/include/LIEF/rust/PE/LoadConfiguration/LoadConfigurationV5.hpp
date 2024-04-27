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
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV5.hpp"
#include "LIEF/rust/PE/LoadConfiguration/LoadConfigurationV4.hpp"

class PE_LoadConfigurationV5 : public PE_LoadConfigurationV4 {
  public:
  using lief_t = LIEF::PE::LoadConfigurationV5;
  PE_LoadConfigurationV5(const lief_t& base) : PE_LoadConfigurationV4(base) {}

  uint64_t guard_rf_failure_routine() const { return impl().guard_rf_failure_routine(); }
  uint64_t guard_rf_failure_routine_function_pointer() const { return impl().guard_rf_failure_routine_function_pointer(); }
  uint32_t dynamic_value_reloctable_offset() const { return impl().dynamic_value_reloctable_offset(); }
  uint16_t dynamic_value_reloctable_section() const { return impl().dynamic_value_reloctable_section(); }
  uint16_t reserved2() const { return impl().reserved2(); }

  static bool classof(const PE_LoadConfiguration& config) {
    return lief_t::classof(&config.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
