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
#ifndef LIEF_PE_LOAD_CONFIGURATION_V7_H
#define LIEF_PE_LOAD_CONFIGURATION_V7_H
#include <ostream>

#include "LIEF/visibility.h"

#include "LIEF/PE/LoadConfigurations/LoadConfigurationV6.hpp"

namespace LIEF {
namespace PE {

namespace details {
template<class T>
struct load_configuration_v7;
}

class LIEF_API LoadConfigurationV7 : public LoadConfigurationV6 {
  public:

  static constexpr VERSION WIN_VERSION = VERSION::WIN_10_0_16237;
  LoadConfigurationV7() = default;

  template<class T>
  LIEF_LOCAL LoadConfigurationV7(const details::load_configuration_v7<T>& header);

  LoadConfigurationV7& operator=(const LoadConfigurationV7&) = default;
  LoadConfigurationV7(const LoadConfigurationV7&) = default;

  VERSION version() const override {
    return WIN_VERSION;
  }

  uint32_t reserved3() const {
    return reserved3_;
  }
  uint64_t addressof_unicode_string() const {
    return addressof_unicode_string_;
  }

  void reserved3(uint32_t value) {
    reserved3_ = value;
  }
  void addressof_unicode_string(uint64_t value) {
    addressof_unicode_string_ = value;
  }

  static bool classof(const LoadConfiguration* config) {
    return config->version() == WIN_VERSION;
  }

  ~LoadConfigurationV7() override = default;

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  protected:
  uint32_t reserved3_ = 0;
  uint64_t addressof_unicode_string_ = 0;
};
}
}

#endif
