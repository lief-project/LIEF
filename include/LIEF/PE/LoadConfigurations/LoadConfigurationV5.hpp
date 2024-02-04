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
#ifndef LIEF_PE_LOAD_CONFIGURATION_V5_H
#define LIEF_PE_LOAD_CONFIGURATION_V5_H
#include <ostream>

#include "LIEF/visibility.h"
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV4.hpp"

namespace LIEF {
namespace PE {

namespace details {
template<class T>
struct load_configuration_v5;
}

//! @brief Load Configuration enhanced with Return Flow Guard
class LIEF_API LoadConfigurationV5 : public LoadConfigurationV4 {
  public:
  static constexpr VERSION WIN_VERSION = VERSION::WIN_10_0_14901;
  LoadConfigurationV5() = default;

  template<class T>
  LIEF_LOCAL LoadConfigurationV5(const details::load_configuration_v5<T>& header);

  LoadConfigurationV5& operator=(const LoadConfigurationV5&) = default;
  LoadConfigurationV5(const LoadConfigurationV5&) = default;

  VERSION version() const override {
    return WIN_VERSION;
  }

  //! @brief VA of the failure routine
  uint64_t guard_rf_failure_routine() const {
    return guard_rf_failure_routine_;
  }

  //! @brief VA of the failure routine ``fptr``.
  uint64_t guard_rf_failure_routine_function_pointer() const {
    return guard_rf_failure_routine_function_pointer_;
  }

  //! @brief Offset of dynamic relocation table relative to the relocation table
  uint32_t dynamic_value_reloctable_offset() const {
    return dynamic_value_reloctable_offset_;
  }

  //! The section index of the dynamic value relocation table
  uint16_t dynamic_value_reloctable_section() const {
    return dynamic_value_reloctable_section_;
  }

  //! @brief Must be zero
  uint16_t reserved2() const {
    return reserved2_;
  }

  void guard_rf_failure_routine(uint64_t value) {
    guard_rf_failure_routine_ = value;
  }

  void guard_rf_failure_routine_function_pointer(uint64_t value) {
    guard_rf_failure_routine_function_pointer_ = value;
  }

  void dynamic_value_reloctable_offset(uint32_t value) {
    dynamic_value_reloctable_offset_ = value;
  }

  void dynamic_value_reloctable_section(uint16_t value) {
    dynamic_value_reloctable_section_ = value;
  }

  void reserved2(uint16_t value) {
    reserved2_ = value;
  }

  static bool classof(const LoadConfiguration* config) {
    return config->version() == WIN_VERSION;
  }

  ~LoadConfigurationV5() override = default;

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  protected:
  uint64_t guard_rf_failure_routine_ = 0;
  uint64_t guard_rf_failure_routine_function_pointer_ = 0;
  uint32_t dynamic_value_reloctable_offset_ = 0;
  uint16_t dynamic_value_reloctable_section_ = 0;
  uint16_t reserved2_ = 0;
};
}
}

#endif
