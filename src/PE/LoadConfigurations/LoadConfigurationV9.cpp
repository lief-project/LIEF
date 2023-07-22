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

#include "LIEF/PE/LoadConfigurations/LoadConfigurationV9.hpp"

namespace LIEF {
namespace PE {

LoadConfigurationV9& LoadConfigurationV9::operator=(const LoadConfigurationV9&) = default;
LoadConfigurationV9::LoadConfigurationV9(const LoadConfigurationV9&) = default;
LoadConfigurationV9::~LoadConfigurationV9() = default;

LoadConfigurationV9::LoadConfigurationV9() = default;

void LoadConfigurationV9::accept(Visitor& visitor) const {
  visitor.visit(*this);
}



std::ostream& LoadConfigurationV9::print(std::ostream& os) const {
  LoadConfigurationV8::print(os);

  os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') <<
        "GuardEH Continuation Table:" << std::hex << guard_eh_continuation_table() << '\n'
     << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') <<
        "GuardEH Continuation Count:" << std::dec << guard_eh_continuation_count() << '\n';
  return os;
}


} // namespace PE
} // namespace LIEF

