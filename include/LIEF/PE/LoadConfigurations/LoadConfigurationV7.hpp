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
#ifndef LIEF_PE_LOAD_CONFIGURATION_V7_H_
#define LIEF_PE_LOAD_CONFIGURATION_V7_H_
#include <array>
#include <functional>
#include <algorithm>
#include <iostream>

#include "LIEF/visibility.h"

#include "LIEF/PE/Structures.hpp"
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV6.hpp"

namespace LIEF {
namespace PE {
class LIEF_API LoadConfigurationV7 : public LoadConfigurationV6 {
  public:

  static constexpr WIN_VERSION VERSION = WIN_VERSION::WIN10_0_16237;
  LoadConfigurationV7(void);

  template<class T>
  LIEF_LOCAL LoadConfigurationV7(const load_configuration_v7<T>* header);

  LoadConfigurationV7& operator=(const LoadConfigurationV7&);
  LoadConfigurationV7(const LoadConfigurationV7&);

  virtual WIN_VERSION version(void) const override;

  uint32_t reserved3(void) const;
  uint64_t addressof_unicode_string(void) const;

  void reserved3(uint32_t value);
  void addressof_unicode_string(uint64_t value);

  virtual ~LoadConfigurationV7(void);

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const LoadConfigurationV7& rhs) const;
  bool operator!=(const LoadConfigurationV7& rhs) const;

  virtual std::ostream& print(std::ostream& os) const override;

  protected:
  uint32_t reserved3_;
  uint64_t addressof_unicode_string_;
};
}
}

#endif
