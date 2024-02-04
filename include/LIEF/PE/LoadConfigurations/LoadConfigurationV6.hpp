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
#ifndef LIEF_PE_LOAD_CONFIGURATION_V6_H
#define LIEF_PE_LOAD_CONFIGURATION_V6_H
#include <ostream>

#include "LIEF/visibility.h"

#include "LIEF/PE/LoadConfigurations/LoadConfigurationV5.hpp"

namespace LIEF {
namespace PE {

namespace details {
template<class T>
struct load_configuration_v6;
}

//! @brief Load Configuration enhanced with Hotpatch and improved RFG
class LIEF_API LoadConfigurationV6 : public LoadConfigurationV5 {
  public:
  static constexpr VERSION WIN_VERSION = VERSION::WIN_10_0_15002;

  LoadConfigurationV6() = default;

  template<class T>
  LIEF_LOCAL LoadConfigurationV6(const details::load_configuration_v6<T>& header);

  LoadConfigurationV6& operator=(const LoadConfigurationV6&) = default;
  LoadConfigurationV6(const LoadConfigurationV6&) = default;

  VERSION version() const override {
    return WIN_VERSION;
  }

  //! @brief VA of the Function verifying the stack pointer
  uint64_t guard_rf_verify_stackpointer_function_pointer() const {
    return guardrf_verify_stackpointer_function_pointer_;
  }

  //! @brief Offset to the *hotpatch* table
  uint32_t hotpatch_table_offset() const {
    return hotpatch_table_offset_;
  }

  void guard_rf_verify_stackpointer_function_pointer(uint64_t value) {
    guardrf_verify_stackpointer_function_pointer_ = value;
  }
  void hotpatch_table_offset(uint32_t value) {
    hotpatch_table_offset_ = value;
  }

  static bool classof(const LoadConfiguration* config) {
    return config->version() == WIN_VERSION;
  }

  ~LoadConfigurationV6() override = default;

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  protected:
  uint64_t guardrf_verify_stackpointer_function_pointer_ = 0;
  uint32_t hotpatch_table_offset_ = 0;
};
}
}

#endif
