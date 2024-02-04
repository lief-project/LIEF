/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#ifndef LIEF_PE_LOAD_CONFIGURATION_V3_H
#define LIEF_PE_LOAD_CONFIGURATION_V3_H
#include <ostream>

#include "LIEF/visibility.h"
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV2.hpp"

namespace LIEF {
namespace PE {

namespace details {
template<class T>
struct load_configuration_v3;
}

//! @brief LoadConfiguration with Control Flow Guard improved
class LIEF_API LoadConfigurationV3 : public LoadConfigurationV2 {
  public:

  static constexpr VERSION WIN_VERSION = VERSION::WIN_10_0_14286;

  LoadConfigurationV3() = default;

  template<class T>
  LIEF_LOCAL LoadConfigurationV3(const details::load_configuration_v3<T>& header);

  LoadConfigurationV3& operator=(const LoadConfigurationV3&) = default;
  LoadConfigurationV3(const LoadConfigurationV3&) = default;

  VERSION version() const override {
    return WIN_VERSION;
  }

  //! @brief VA of a table associated with CFG's *IAT* checks
  uint64_t guard_address_taken_iat_entry_table() const {
    return guard_address_taken_iat_entry_table_;
  }

  //! @brief Number of entries in the LoadConfigurationV3::guard_address_taken_iat_entry_table
  uint64_t guard_address_taken_iat_entry_count() const {
    return guard_address_taken_iat_entry_count_;
  }

  //! @brief VA of a table associated with CFG's *long jump*
  uint64_t guard_long_jump_target_table() const {
    return guard_long_jump_target_table_;
  }

  //! @brief Number of entries in the LoadConfigurationV3::guard_long_jump_target_table
  uint64_t guard_long_jump_target_count() const {
    return guard_long_jump_target_count_;
  }

  void guard_address_taken_iat_entry_table(uint64_t value) {
    guard_address_taken_iat_entry_table_ = value;
  }

  void guard_address_taken_iat_entry_count(uint64_t value) {
    guard_address_taken_iat_entry_count_ = value;
  }

  void guard_long_jump_target_table(uint64_t value) {
    guard_long_jump_target_table_ = value;
  }

  void guard_long_jump_target_count(uint64_t value) {
    guard_long_jump_target_count_ = value;
  }

  static bool classof(const LoadConfiguration* config) {
    return config->version() == WIN_VERSION;
  }

  ~LoadConfigurationV3() override = default;

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  protected:
  uint64_t guard_address_taken_iat_entry_table_ = 0;
  uint64_t guard_address_taken_iat_entry_count_ = 0;
  uint64_t guard_long_jump_target_table_ = 0;
  uint64_t guard_long_jump_target_count_ = 0;
};
}
}

#endif
