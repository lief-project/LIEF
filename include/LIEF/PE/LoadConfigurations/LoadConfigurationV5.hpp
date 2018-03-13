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
#ifndef LIEF_PE_LOAD_CONFIGURATION_V5_H_
#define LIEF_PE_LOAD_CONFIGURATION_V5_H_
#include <array>
#include <set>
#include <functional>
#include <algorithm>
#include <iostream>

#include "LIEF/visibility.h"

#include "LIEF/PE/Structures.hpp"
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV4.hpp"

namespace LIEF {
namespace PE {

//! @brief Load Configuration enhanced with Return Flow Guard
class LIEF_API LoadConfigurationV5 : public LoadConfigurationV4 {
  public:
  static constexpr WIN_VERSION VERSION = WIN_VERSION::WIN10_0_14901;
  LoadConfigurationV5(void);

  template<class T>
  LIEF_LOCAL LoadConfigurationV5(const load_configuration_v5<T>* header);

  LoadConfigurationV5& operator=(const LoadConfigurationV5&);
  LoadConfigurationV5(const LoadConfigurationV5&);

  virtual WIN_VERSION version(void) const override;

  //! @brief VA of the failure routine
  uint64_t guard_rf_failure_routine(void) const;

  //! @brief VA of the failure routine ``fptr``.
  uint64_t guard_rf_failure_routine_function_pointer(void) const;

  //! @brief Offset of dynamic relocation table relative to the relocation table
  uint32_t dynamic_value_reloctable_offset(void) const;

  //! The section index of the dynamic value relocation table
  uint16_t dynamic_value_reloctable_section(void) const;

  //! @brief Must be zero
  uint16_t reserved2(void) const;

  void guard_rf_failure_routine(uint64_t value);
  void guard_rf_failure_routine_function_pointer(uint64_t value);
  void dynamic_value_reloctable_offset(uint32_t value);
  void dynamic_value_reloctable_section(uint16_t value);
  void reserved2(uint16_t value);

  virtual ~LoadConfigurationV5(void);

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const LoadConfigurationV5& rhs) const;
  bool operator!=(const LoadConfigurationV5& rhs) const;

  virtual std::ostream& print(std::ostream& os) const override;

  protected:
  uint64_t guard_rf_failure_routine_;
  uint64_t guard_rf_failure_routine_function_pointer_;
  uint32_t dynamic_value_reloctable_offset_;
  uint16_t dynamic_value_reloctable_section_;
  uint16_t reserved2_;
};
}
}

#endif
