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
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV11.hpp"
#include "LIEF/Visitor.hpp"
#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

template<class T>
LoadConfigurationV11::LoadConfigurationV11(const details::load_configuration_v11<T>& header) :
  LoadConfigurationV10{static_cast<const details::load_configuration_v10<T>&>(header)},
  cast_guard_os_determined_failure_mode_{header.CastGuardOsDeterminedFailureMode}
{}

void LoadConfigurationV11::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& LoadConfigurationV11::print(std::ostream& os) const {
  LoadConfigurationV10::print(os);

  os << "LoadConfigurationV11:\n"
     << fmt::format("  Cast Guard OS Determined Failure Mode: 0x{:08x}\n", cast_guard_os_determined_failure_mode());
  return os;
}

template
LoadConfigurationV11::LoadConfigurationV11(const details::load_configuration_v11<uint32_t>& header);
template
LoadConfigurationV11::LoadConfigurationV11(const details::load_configuration_v11<uint64_t>& header);



} // namespace PE
} // namespace LIEF

