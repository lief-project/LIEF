/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#ifndef LIEF_PE_LOAD_CONFIGURATION_V2_H_
#define LIEF_PE_LOAD_CONFIGURATION_V2_H_
#include <iostream>

#include "LIEF/visibility.h"

#include "LIEF/PE/enums.hpp"
#include "LIEF/PE/CodeIntegrity.hpp"
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV1.hpp"

namespace LIEF {
namespace PE {

namespace details {
template<class T>
struct load_configuration_v2;
}

//! @brief LoadConfiguration enhanced with code integrity
class LIEF_API LoadConfigurationV2 : public LoadConfigurationV1 {
  public:
  static constexpr WIN_VERSION VERSION = WIN_VERSION::WIN10_0_9879;
  LoadConfigurationV2();

  LoadConfigurationV2& operator=(const LoadConfigurationV2&);
  LoadConfigurationV2(const LoadConfigurationV2&);

  template<class T>
  LIEF_LOCAL LoadConfigurationV2(const details::load_configuration_v2<T>& header);

  WIN_VERSION version() const override;

  //! @brief CodeIntegrity associated with
  const CodeIntegrity& code_integrity() const;
  CodeIntegrity& code_integrity();

  virtual ~LoadConfigurationV2();

  void accept(Visitor& visitor) const override;

  bool operator==(const LoadConfigurationV2& rhs) const;
  bool operator!=(const LoadConfigurationV2& rhs) const;

  std::ostream& print(std::ostream& os) const override;

  protected:
  CodeIntegrity code_integrity_;
};
}
}

#endif
