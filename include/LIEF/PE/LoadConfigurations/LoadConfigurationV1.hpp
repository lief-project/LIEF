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
#ifndef LIEF_PE_LOAD_CONFIGURATION_V1_H_
#define LIEF_PE_LOAD_CONFIGURATION_V1_H_
#include <iostream>
#include <set>

#include "LIEF/visibility.h"

#include "LIEF/PE/enums.hpp"
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV0.hpp"

namespace LIEF {
namespace PE {

namespace details {
template<class T>
struct load_configuration_v1;
}

//! @brief LoadConfiguration enhanced with Control Flow Guard
//!
//! This structure is available from Windows 8.1
class LIEF_API LoadConfigurationV1 : public LoadConfigurationV0 {
  public:
  static constexpr WIN_VERSION VERSION = WIN_VERSION::WIN8_1;

  template<class T>
  using flags_list_t = std::set<T>;

  using guard_cf_flags_list_t = flags_list_t<GUARD_CF_FLAGS>;

  LoadConfigurationV1();

  template<class T>
  LIEF_LOCAL LoadConfigurationV1(const details::load_configuration_v1<T>& header);

  LoadConfigurationV1& operator=(const LoadConfigurationV1&);
  LoadConfigurationV1(const LoadConfigurationV1&);

  WIN_VERSION version() const override;

  //! @brief The VA where Control Flow Guard check-function pointer is stored.
  uint64_t guard_cf_check_function_pointer() const;

  //! @brief The VA where Control Flow Guard dispatch-function pointer is stored.
  uint64_t guard_cf_dispatch_function_pointer() const;

  //! @brief The VA of the sorted table of RVAs of each Control Flow Guard
  //! function in the image.
  uint64_t guard_cf_function_table() const;

  //! @brief The count of unique RVAs in the
  //! LoadConfigurationV1::guard_cf_function_table.
  uint64_t guard_cf_function_count() const;

  //! @brief Control Flow Guard related flags.
  GUARD_CF_FLAGS guard_flags() const;

  //! @brief Check if the given flag is present in LoadConfigurationV1::guard_flags
  bool has(GUARD_CF_FLAGS flag) const;

  //! @brief LoadConfigurationV1::guard_flags as a list of LIEF::PE::GUARD_CF_FLAGS
  guard_cf_flags_list_t guard_cf_flags_list() const;

  void guard_cf_check_function_pointer(uint64_t guard_cf_check_function_pointer);
  void guard_cf_dispatch_function_pointer(uint64_t guard_cf_dispatch_function_pointer);
  void guard_cf_function_table(uint64_t guard_cf_function_table);
  void guard_cf_function_count(uint64_t guard_cf_function_count);
  void guard_flags(GUARD_CF_FLAGS guard_flags);

  virtual ~LoadConfigurationV1();

  void accept(Visitor& visitor) const override;

  bool operator==(const LoadConfigurationV1& rhs) const;
  bool operator!=(const LoadConfigurationV1& rhs) const;

  std::ostream& print(std::ostream& os) const override;

  protected:
  uint64_t guard_cf_check_function_pointer_;
  uint64_t guard_cf_dispatch_function_pointer_;
  uint64_t guard_cf_function_table_;
  uint64_t guard_cf_function_count_;
  GUARD_CF_FLAGS guard_flags_;
};
}
}

#endif
