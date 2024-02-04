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
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV8.hpp"
#include "LIEF/Visitor.hpp"

#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

template<class T>
LoadConfigurationV8::LoadConfigurationV8(const details::load_configuration_v8<T>& header) :
  LoadConfigurationV7{static_cast<const details::load_configuration_v7<T>&>(header)},
  volatile_metadata_pointer_{header.VolatileMetadataPointer}
{
}

void LoadConfigurationV8::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& LoadConfigurationV8::print(std::ostream& os) const {
  LoadConfigurationV7::print(os);
  os << "LoadConfigurationV8:\n"
     << fmt::format("  Volatile Metadata Pointer: 0x{:08x}\n", volatile_metadata_pointer());
  return os;
}

template
LoadConfigurationV8::LoadConfigurationV8(const details::load_configuration_v8<uint32_t>& header);
template
LoadConfigurationV8::LoadConfigurationV8(const details::load_configuration_v8<uint64_t>& header);


} // namespace PE
} // namespace LIEF

