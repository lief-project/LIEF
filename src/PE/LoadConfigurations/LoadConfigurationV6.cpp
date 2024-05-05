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
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV6.hpp"
#include "LIEF/Visitor.hpp"

#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

template<class T>
LoadConfigurationV6::LoadConfigurationV6(const details::load_configuration_v6<T>& header) :
  LoadConfigurationV5{reinterpret_cast<const details::load_configuration_v5<T>&>(header)},
  guardrf_verify_stackpointer_function_pointer_{header.GuardRFVerifyStackPointerFunctionPointer},
  hotpatch_table_offset_{header.HotPatchTableOffset}
{}

void LoadConfigurationV6::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& LoadConfigurationV6::print(std::ostream& os) const {
  LoadConfigurationV5::print(os);

  os << "LoadConfigurationV6:\n"
     << fmt::format("  GRF verify stackpointer function pointer   0x{:08x}\n", guard_rf_verify_stackpointer_function_pointer())
     << fmt::format("  Hotpatch table offset                      0x{:08x}\n", hotpatch_table_offset());
  //os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "GRF verify stackpointer function pointer:" << std::hex << guard_rf_verify_stackpointer_function_pointer() << '\n';
  //os << std::setw(LoadConfiguration::PRINT_WIDTH) << std::setfill(' ') << "Hotpatch table offset:"                    << std::hex << hotpatch_table_offset()                         << '\n';
  return os;
}

template
LoadConfigurationV6::LoadConfigurationV6(const details::load_configuration_v6<uint32_t>& header);
template
LoadConfigurationV6::LoadConfigurationV6(const details::load_configuration_v6<uint64_t>& header);

} // namespace PE
} // namespace LIEF

