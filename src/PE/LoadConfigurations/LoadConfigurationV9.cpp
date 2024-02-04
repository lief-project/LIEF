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
#include <spdlog/fmt/fmt.h>
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV9.hpp"
#include "LIEF/Visitor.hpp"

#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

template<class T>
LoadConfigurationV9::LoadConfigurationV9(const details::load_configuration_v9<T>& header) :
  LoadConfigurationV8{static_cast<const details::load_configuration_v8<T>&>(header)},
  guard_eh_continuation_table_{header.GuardEHContinuationTable},
  guard_eh_continuation_count_{header.GuardEHContinuationCount}
{}


void LoadConfigurationV9::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& LoadConfigurationV9::print(std::ostream& os) const {
  LoadConfigurationV8::print(os);

  os << "LoadConfigurationV9:\n"
     << fmt::format("  GuardEH Continuation Table: 0x{:08x}\n", guard_eh_continuation_table())
     << fmt::format("  GuardEH Continuation Count: {}\n", guard_eh_continuation_count());
  return os;
}

template
LoadConfigurationV9::LoadConfigurationV9(const details::load_configuration_v9<uint32_t>& header);
template
LoadConfigurationV9::LoadConfigurationV9(const details::load_configuration_v9<uint64_t>& header);

} // namespace PE
} // namespace LIEF

