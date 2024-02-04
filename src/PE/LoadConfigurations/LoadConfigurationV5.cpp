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
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV5.hpp"
#include "LIEF/Visitor.hpp"
#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

template<class T>
LoadConfigurationV5::LoadConfigurationV5(const details::load_configuration_v5<T>& header) :
  LoadConfigurationV4{reinterpret_cast<const details::load_configuration_v4<T>&>(header)},
  guard_rf_failure_routine_{header.GuardRFFailureRoutine},
  guard_rf_failure_routine_function_pointer_{header.GuardRFFailureRoutineFunctionPointer},
  dynamic_value_reloctable_offset_{header.DynamicValueRelocTableOffset},
  dynamic_value_reloctable_section_{header.DynamicValueRelocTableSection},
  reserved2_{header.Reserved2}
{}


void LoadConfigurationV5::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& LoadConfigurationV5::print(std::ostream& os) const {
  LoadConfigurationV4::print(os);

  os << "LoadConfigurationV5:\n"
     << fmt::format("  GRF failure routine                  0x{:08x}\n", guard_rf_failure_routine())
     << fmt::format("  GRF failure routine function pointer 0x{:08x}\n", guard_rf_failure_routine_function_pointer())
     << fmt::format("  Dynamic value reloctable offset      0x{:08x}\n", dynamic_value_reloctable_offset())
     << fmt::format("  Dynamic value reloctable section     {}\n", dynamic_value_reloctable_section());
  return os;
}

template
LoadConfigurationV5::LoadConfigurationV5(const details::load_configuration_v5<uint32_t>& header);
template
LoadConfigurationV5::LoadConfigurationV5(const details::load_configuration_v5<uint64_t>& header);

} // namespace PE
} // namespace LIEF

