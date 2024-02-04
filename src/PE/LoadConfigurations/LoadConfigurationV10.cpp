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
#include "LIEF/Visitor.hpp"
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV10.hpp"

#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

template<class T>
LoadConfigurationV10::LoadConfigurationV10(const details::load_configuration_v10<T>& header) :
  LoadConfigurationV9{static_cast<const details::load_configuration_v9<T>&>(header)},
  guard_xfg_check_function_pointer_{header.GuardXFGCheckFunctionPointer},
  guard_xfg_dispatch_function_pointer_{header.GuardXFGDispatchFunctionPointer},
  guard_xfg_table_dispatch_function_pointer_{header.GuardXFGTableDispatchFunctionPointer}
{
}

void LoadConfigurationV10::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& LoadConfigurationV10::print(std::ostream& os) const {
  LoadConfigurationV9::print(os);

  os << "LoadConfigurationV10:\n"
     << fmt::format("  Guard XFG Check Function Pointer:          0x{:08x}\n", guard_xfg_check_function_pointer())
     << fmt::format("  Guard XFG Dispatch Function Pointer:       {}\n", guard_xfg_dispatch_function_pointer())
     << fmt::format("  Guard XFG Table Dispatch Function Pointer: {}\n", guard_xfg_table_dispatch_function_pointer());
  return os;
}

template
LoadConfigurationV10::LoadConfigurationV10(const details::load_configuration_v10<uint32_t>& header);
template
LoadConfigurationV10::LoadConfigurationV10(const details::load_configuration_v10<uint64_t>& header);


} // namespace PE
} // namespace LIEF

