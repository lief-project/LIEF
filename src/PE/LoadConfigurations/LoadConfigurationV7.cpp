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
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV7.hpp"
#include "LIEF/Visitor.hpp"

#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

template<class T>
LoadConfigurationV7::LoadConfigurationV7(const details::load_configuration_v7<T>& header) :
  LoadConfigurationV6{reinterpret_cast<const details::load_configuration_v6<T>&>(header)},
  reserved3_{header.Reserved3},
  addressof_unicode_string_{header.AddressOfSomeUnicodeString}
{
}

void LoadConfigurationV7::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& LoadConfigurationV7::print(std::ostream& os) const {
  LoadConfigurationV6::print(os);
  os << "LoadConfigurationV7:\n"
     << fmt::format("  Reserved 3                0x{:08x}\n", reserved3())
     << fmt::format("  Addressof Unicode String  0x{:08x}\n", addressof_unicode_string());
  return os;
}

template
LoadConfigurationV7::LoadConfigurationV7(const details::load_configuration_v7<uint32_t>& header);
template
LoadConfigurationV7::LoadConfigurationV7(const details::load_configuration_v7<uint64_t>& header);

} // namespace PE
} // namespace LIEF

