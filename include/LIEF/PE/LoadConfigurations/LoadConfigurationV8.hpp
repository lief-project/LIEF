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
#ifndef LIEF_PE_LOAD_CONFIGURATION_V8_H
#define LIEF_PE_LOAD_CONFIGURATION_V8_H
#include <ostream>

#include "LIEF/visibility.h"

#include "LIEF/PE/enums.hpp"
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV7.hpp"

namespace LIEF {
namespace PE {

namespace details {
template<class T>
struct load_configuration_v8;
}

class LIEF_API LoadConfigurationV8 : public LoadConfigurationV7 {
  public:

  static constexpr VERSION WIN_VERSION = VERSION::WIN_10_0_18362;
  LoadConfigurationV8() = default;

  template<class T>
  LIEF_LOCAL LoadConfigurationV8(const details::load_configuration_v8<T>& header);

  LoadConfigurationV8& operator=(const LoadConfigurationV8&) = default;
  LoadConfigurationV8(const LoadConfigurationV8&) = default;

  VERSION version() const override {
    return WIN_VERSION;
  }

  uint64_t volatile_metadata_pointer() const {
    return volatile_metadata_pointer_;
  }

  void volatile_metadata_pointer(uint64_t value) {
    volatile_metadata_pointer_ = value;
  }

  static bool classof(const LoadConfiguration* config) {
    return config->version() == WIN_VERSION;
  }

  ~LoadConfigurationV8() override = default;

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  protected:
  uint64_t volatile_metadata_pointer_ = 0;
};
}
}

#endif
