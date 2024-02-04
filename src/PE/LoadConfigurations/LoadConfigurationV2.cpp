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
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV2.hpp"

#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

template<class T>
LoadConfigurationV2::LoadConfigurationV2(const details::load_configuration_v2<T>& header) :
  LoadConfigurationV1{reinterpret_cast<const details::load_configuration_v1<T>&>(header)},
  code_integrity_{header.CodeIntegrity}
{}

void LoadConfigurationV2::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& LoadConfigurationV2::print(std::ostream& os) const {
  LoadConfigurationV1::print(os);
  os << "LoadConfigurationV2 (CodeIntegrity):\n"
     << code_integrity();
  return os;
}

template
LoadConfigurationV2::LoadConfigurationV2(const details::load_configuration_v2<uint32_t>& header);
template
LoadConfigurationV2::LoadConfigurationV2(const details::load_configuration_v2<uint64_t>& header);

} // namespace PE
} // namespace LIEF

