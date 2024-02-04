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
#ifndef LIEF_PE_LOAD_CONFIGURATION_V0_H
#define LIEF_PE_LOAD_CONFIGURATION_V0_H
#include <ostream>

#include "LIEF/visibility.h"
#include "LIEF/PE/LoadConfigurations/LoadConfiguration.hpp"

namespace LIEF {
namespace PE {

namespace details {
template<class T>
struct load_configuration_v0;
}

//! LoadConfiguration enhanced with SEH
class LIEF_API LoadConfigurationV0 : public LoadConfiguration {
  public:
  static constexpr VERSION WIN_VERSION = VERSION::SEH;

  LoadConfigurationV0() = default;

  LoadConfigurationV0& operator=(const LoadConfigurationV0&) = default;
  LoadConfigurationV0(const LoadConfigurationV0&) = default;

  template<class T>
  LIEF_LOCAL LoadConfigurationV0(const details::load_configuration_v0<T>& header);

  VERSION version() const override {
    return WIN_VERSION;
  }

  //! The VA of the sorted table of RVAs of each valid, unique
  //! SE handler in the image.
  uint64_t se_handler_table() const {
    return se_handler_table_;
  }

  //! The count of unique handlers in the table.
  uint64_t se_handler_count() const {
    return se_handler_count_;
  }

  void se_handler_table(uint64_t se_handler_table) {
    se_handler_table_ = se_handler_table;
  }
  void se_handler_count(uint64_t se_handler_count) {
    se_handler_count_ = se_handler_count;
  }

  ~LoadConfigurationV0() override = default;

  static bool classof(const LoadConfiguration* config) {
    return config->version() == WIN_VERSION;
  }

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  protected:
  uint64_t se_handler_table_ = 0;
  uint64_t se_handler_count_ = 0;
};
}
}

#endif
