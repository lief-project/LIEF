/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
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
#include <iomanip>

#include "LIEF/PE/hash.hpp"

#include "LIEF/PE/LoadConfigurations/LoadConfigurationV11.hpp"

namespace LIEF {
namespace PE {

LoadConfigurationV11& LoadConfigurationV11::operator=(const LoadConfigurationV11&) = default;
LoadConfigurationV11::LoadConfigurationV11(const LoadConfigurationV11&) = default;
LoadConfigurationV11::~LoadConfigurationV11() = default;

LoadConfigurationV11::LoadConfigurationV11() = default;

void LoadConfigurationV11::accept(Visitor& visitor) const {
  visitor.visit(*this);
}



std::ostream& LoadConfigurationV11::print(std::ostream& os) const {
  LoadConfigurationV10::print(os);

  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') <<
        "Cast Guard OS Determined Failure Mode:" << std::hex << cast_guard_os_determined_failure_mode() << std::endl;
  return os;
}


} // namespace PE
} // namespace LIEF

