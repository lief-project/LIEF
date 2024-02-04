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
#ifndef LIEF_PE_LOAD_CONFIGURATION_V10_H
#define LIEF_PE_LOAD_CONFIGURATION_V10_H
#include <ostream>

#include "LIEF/visibility.h"

#include "LIEF/PE/LoadConfigurations/LoadConfigurationV9.hpp"

namespace LIEF {
namespace PE {

namespace details {
template<class T>
struct load_configuration_v10;
}

class LIEF_API LoadConfigurationV10 : public LoadConfigurationV9 {
  public:

  static constexpr VERSION WIN_VERSION = VERSION::WIN_10_0_MSVC_2019;
  LoadConfigurationV10() = default;

  template<class T>
  LIEF_LOCAL LoadConfigurationV10(const details::load_configuration_v10<T>& header);

  LoadConfigurationV10& operator=(const LoadConfigurationV10&) = default;
  LoadConfigurationV10(const LoadConfigurationV10&) = default;

  VERSION version() const override {
    return WIN_VERSION;
  }

  uint64_t guard_xfg_check_function_pointer() const {
    return guard_xfg_check_function_pointer_;
  }

  uint64_t guard_xfg_dispatch_function_pointer() const {
    return guard_xfg_dispatch_function_pointer_;
  }

  uint64_t guard_xfg_table_dispatch_function_pointer() const {
    return guard_xfg_table_dispatch_function_pointer_;
  }

  void guard_xfg_check_function_pointer(uint64_t value) {
    guard_xfg_check_function_pointer_ = value;
  }

  void guard_xfg_dispatch_function_pointer(uint64_t value) {
    guard_xfg_dispatch_function_pointer_ = value;
  }

  void guard_xfg_table_dispatch_function_pointer(uint64_t value) {
    guard_xfg_table_dispatch_function_pointer_ = value;
  }

  static bool classof(const LoadConfiguration* config) {
    return config->version() == WIN_VERSION;
  }

  ~LoadConfigurationV10() override = default;

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  protected:
  uint64_t guard_xfg_check_function_pointer_ = 0;
  uint64_t guard_xfg_dispatch_function_pointer_ = 0;
  uint64_t guard_xfg_table_dispatch_function_pointer_ = 0;
};
}
}

#endif
