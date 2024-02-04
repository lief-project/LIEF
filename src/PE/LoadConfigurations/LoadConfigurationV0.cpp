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
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV0.hpp"
#include "LIEF/Visitor.hpp"

#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

template<class T>
LoadConfigurationV0::LoadConfigurationV0(const details::load_configuration_v0<T>& header) :
  LoadConfiguration{reinterpret_cast<const details::load_configuration<T>&>(header)},
  se_handler_table_{header.SEHandlerTable},
  se_handler_count_{header.SEHandlerCount}
{}

void LoadConfigurationV0::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& LoadConfigurationV0::print(std::ostream& os) const {
  LoadConfiguration::print(os);
  os << "LoadConfigurationV0:\n"
     << fmt::format("  SE handler table 0x{:06x}\n", se_handler_table())
     << fmt::format("  SE handler count {}\n", se_handler_count());
  return os;
}

template
LoadConfigurationV0::LoadConfigurationV0(const details::load_configuration_v0<uint32_t>& header);
template
LoadConfigurationV0::LoadConfigurationV0(const details::load_configuration_v0<uint64_t>& header);

} // namespace PE
} // namespace LIEF

