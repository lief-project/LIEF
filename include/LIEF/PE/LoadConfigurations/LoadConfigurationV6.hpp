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
#ifndef LIEF_PE_LOAD_CONFIGURATION_V6_H_
#define LIEF_PE_LOAD_CONFIGURATION_V6_H_
#include <array>
#include <set>
#include <functional>
#include <algorithm>
#include <iostream>

#include "LIEF/visibility.h"

#include "LIEF/PE/Structures.hpp"
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV5.hpp"

namespace LIEF {
namespace PE {

//! @brief Load Configuration enhanced with Hotpatch and improved RFG
class LIEF_API LoadConfigurationV6 : public LoadConfigurationV5 {
  public:
  static constexpr WIN_VERSION VERSION = WIN_VERSION::WIN10_0_15002;

  LoadConfigurationV6(void);

  template<class T>
  LIEF_LOCAL LoadConfigurationV6(const load_configuration_v6<T>* header);

  LoadConfigurationV6& operator=(const LoadConfigurationV6&);
  LoadConfigurationV6(const LoadConfigurationV6&);

  virtual WIN_VERSION version(void) const override;

  //! @brief VA of the Function verifying the stack pointer
  uint64_t guard_rf_verify_stackpointer_function_pointer(void) const;

  //! @brief Offset to the *hotpatch* table
  uint32_t hotpatch_table_offset(void) const;

  void guard_rf_verify_stackpointer_function_pointer(uint64_t value);
  void hotpatch_table_offset(uint32_t value);

  virtual ~LoadConfigurationV6(void);

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const LoadConfigurationV6& rhs) const;
  bool operator!=(const LoadConfigurationV6& rhs) const;

  virtual std::ostream& print(std::ostream& os) const override;

  protected:
  uint64_t guardrf_verify_stackpointer_function_pointer_;
  uint32_t hotpatch_table_offset_;
};
}
}

#endif
