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
#ifndef LIEF_PE_LOAD_CONFIGURATION_V4_H_
#define LIEF_PE_LOAD_CONFIGURATION_V4_H_
#include <array>
#include <set>
#include <functional>
#include <algorithm>
#include <iostream>

#include "LIEF/visibility.h"

#include "LIEF/PE/Structures.hpp"
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV3.hpp"

namespace LIEF {
namespace PE {

//! @brief Load Configuration enhanced with
//! * Kind of dynamic relocations
//! * *Hybrid Metadata Pointer*
class LIEF_API LoadConfigurationV4 : public LoadConfigurationV3 {
  public:
  static constexpr WIN_VERSION VERSION = WIN_VERSION::WIN10_0_14383;

  LoadConfigurationV4(void);

  template<class T>
  LIEF_LOCAL LoadConfigurationV4(const load_configuration_v4<T>* header);

  LoadConfigurationV4& operator=(const LoadConfigurationV4&);
  LoadConfigurationV4(const LoadConfigurationV4&);

  virtual WIN_VERSION version(void) const override;

  //! @brief VA of pointing to a ``IMAGE_DYNAMIC_RELOCATION_TABLE``
  uint64_t dynamic_value_reloc_table(void) const;

  uint64_t hybrid_metadata_pointer(void) const;

  void dynamic_value_reloc_table(uint64_t value);
  void hybrid_metadata_pointer(uint64_t value);

  virtual ~LoadConfigurationV4(void);

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const LoadConfigurationV4& rhs) const;
  bool operator!=(const LoadConfigurationV4& rhs) const;

  virtual std::ostream& print(std::ostream& os) const override;

  protected:
  uint64_t dynamic_value_reloc_table_;
  uint64_t hybrid_metadata_pointer_;
};
}
}

#endif
