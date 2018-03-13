/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#ifndef LIEF_PE_LOAD_CONFIGURATION_V3_H_
#define LIEF_PE_LOAD_CONFIGURATION_V3_H_
#include <array>
#include <set>
#include <functional>
#include <algorithm>
#include <iostream>

#include "LIEF/visibility.h"

#include "LIEF/PE/Structures.hpp"
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV2.hpp"

namespace LIEF {
namespace PE {

//! @brief LoadConfiguration with Control Flow Guard improved
class LIEF_API LoadConfigurationV3 : public LoadConfigurationV2 {
  public:

  static constexpr WIN_VERSION VERSION = WIN_VERSION::WIN10_0_14286;

  LoadConfigurationV3(void);

  template<class T>
  LIEF_LOCAL LoadConfigurationV3(const load_configuration_v3<T>* header);

  LoadConfigurationV3& operator=(const LoadConfigurationV3&);
  LoadConfigurationV3(const LoadConfigurationV3&);

  virtual WIN_VERSION version(void) const override;

  //! @brief VA of a table associated with CFG's *IAT* checks
  uint64_t guard_address_taken_iat_entry_table(void) const;

  //! @brief Number of entries in the LoadConfigurationV3::guard_address_taken_iat_entry_table
  uint64_t guard_address_taken_iat_entry_count(void) const;

  //! @brief VA of a table associated with CFG's *long jump*
  uint64_t guard_long_jump_target_table(void) const;

  //! @brief Number of entries in the LoadConfigurationV3::guard_long_jump_target_table
  uint64_t guard_long_jump_target_count(void) const;

  void guard_address_taken_iat_entry_table(uint64_t value);
  void guard_address_taken_iat_entry_count(uint64_t value);
  void guard_long_jump_target_table(uint64_t value);
  void guard_long_jump_target_count(uint64_t value);

  virtual ~LoadConfigurationV3(void);

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const LoadConfigurationV3& rhs) const;
  bool operator!=(const LoadConfigurationV3& rhs) const;

  virtual std::ostream& print(std::ostream& os) const override;

  protected:
  uint64_t guard_address_taken_iat_entry_table_;
  uint64_t guard_address_taken_iat_entry_count_;
  uint64_t guard_long_jump_target_table_;
  uint64_t guard_long_jump_target_count_;
};
}
}

#endif
