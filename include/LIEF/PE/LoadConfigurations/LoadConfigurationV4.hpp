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
#ifndef LIEF_PE_LOAD_CONFIGURATION_V4_H
#define LIEF_PE_LOAD_CONFIGURATION_V4_H
#include <ostream>

#include "LIEF/visibility.h"

#include "LIEF/PE/LoadConfigurations/LoadConfigurationV3.hpp"

namespace LIEF {
namespace PE {

namespace details {
template<class T>
struct load_configuration_v4;
}

//! @brief Load Configuration enhanced with
//! * Kind of dynamic relocations
//! * *Hybrid Metadata Pointer*
class LIEF_API LoadConfigurationV4 : public LoadConfigurationV3 {
  public:
  static constexpr VERSION WIN_VERSION = VERSION::WIN_10_0_14383;

  LoadConfigurationV4() = default;

  template<class T>
  LIEF_LOCAL LoadConfigurationV4(const details::load_configuration_v4<T>& header);

  LoadConfigurationV4& operator=(const LoadConfigurationV4&) = default;
  LoadConfigurationV4(const LoadConfigurationV4&) = default;

  VERSION version() const override {
    return WIN_VERSION;
  }

  //! @brief VA of pointing to a ``IMAGE_DYNAMIC_RELOCATION_TABLE``
  uint64_t dynamic_value_reloc_table() const {
    return dynamic_value_reloc_table_;
  }

  uint64_t hybrid_metadata_pointer() const {
    return hybrid_metadata_pointer_;
  }

  void dynamic_value_reloc_table(uint64_t value) {
    dynamic_value_reloc_table_ = value;
  }

  void hybrid_metadata_pointer(uint64_t value) {
    hybrid_metadata_pointer_ = value;
  }

  static bool classof(const LoadConfiguration* config) {
    return config->version() == WIN_VERSION;
  }

  ~LoadConfigurationV4() override = default;

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  protected:
  uint64_t dynamic_value_reloc_table_ = 0;
  uint64_t hybrid_metadata_pointer_ = 0;
};
}
}

#endif
