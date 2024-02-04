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
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV4.hpp"
#include "LIEF/Visitor.hpp"

#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

template<class T>
LoadConfigurationV4::LoadConfigurationV4(const details::load_configuration_v4<T>& header) :
  LoadConfigurationV3{reinterpret_cast<const details::load_configuration_v3<T>&>(header)},
  dynamic_value_reloc_table_{header.DynamicValueRelocTable},
  hybrid_metadata_pointer_{header.HybridMetadataPointer}
{
}

void LoadConfigurationV4::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& LoadConfigurationV4::print(std::ostream& os) const {
  LoadConfigurationV3::print(os);

  os << "LoadConfigurationV4:\n"
     << fmt::format("  Dynamic value relocation table 0x{:08x}\n", dynamic_value_reloc_table())
     << fmt::format("  Hybrid metadata pointer        0x{:08x}\n", hybrid_metadata_pointer());
  return os;
}

template
LoadConfigurationV4::LoadConfigurationV4(const details::load_configuration_v4<uint32_t>& header);
template
LoadConfigurationV4::LoadConfigurationV4(const details::load_configuration_v4<uint64_t>& header);

} // namespace PE
} // namespace LIEF

