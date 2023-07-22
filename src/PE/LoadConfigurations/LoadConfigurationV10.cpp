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

#include "LIEF/PE/LoadConfigurations/LoadConfigurationV10.hpp"

namespace LIEF {
namespace PE {

LoadConfigurationV10& LoadConfigurationV10::operator=(const LoadConfigurationV10&) = default;
LoadConfigurationV10::LoadConfigurationV10(const LoadConfigurationV10&) = default;
LoadConfigurationV10::~LoadConfigurationV10() = default;

LoadConfigurationV10::LoadConfigurationV10() = default;

void LoadConfigurationV10::accept(Visitor& visitor) const {
  visitor.visit(*this);
}



std::ostream& LoadConfigurationV10::print(std::ostream& os) const {
  LoadConfigurationV9::print(os);

  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') <<
        "Guard XFG Check Function Pointer:" <<
        std::hex << guard_xfg_check_function_pointer() << '\n'
     << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') <<
        "Guard XFG Dispatch Function Pointer:" <<
        std::hex << guard_xfg_dispatch_function_pointer() << '\n'
     << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') <<
        "Guard XFG Table Dispatch Function Pointer:" <<
        std::hex << guard_xfg_table_dispatch_function_pointer() << '\n';
  return os;
}


} // namespace PE
} // namespace LIEF

