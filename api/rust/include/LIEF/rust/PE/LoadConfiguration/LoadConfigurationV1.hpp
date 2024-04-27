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
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV1.hpp"
#include "LIEF/rust/PE/LoadConfiguration/LoadConfigurationV0.hpp"
#include "LIEF/rust/helpers.hpp"

class PE_LoadConfigurationV1 : public PE_LoadConfigurationV0 {
  public:
  using lief_t = LIEF::PE::LoadConfigurationV1;
  PE_LoadConfigurationV1(const lief_t& base) : PE_LoadConfigurationV0(base) {}

  uint64_t guard_cf_check_function_pointer() const { return impl().guard_cf_check_function_pointer(); }
  uint64_t guard_cf_dispatch_function_pointer() const { return impl().guard_cf_dispatch_function_pointer(); }
  uint64_t guard_cf_function_table() const { return impl().guard_cf_function_table(); }
  uint64_t guard_cf_function_count() const { return impl().guard_cf_function_count(); }
  uint32_t guard_flags() const { return to_int(impl().guard_flags()); }

  static bool classof(const PE_LoadConfiguration& config) {
    return lief_t::classof(&config.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
