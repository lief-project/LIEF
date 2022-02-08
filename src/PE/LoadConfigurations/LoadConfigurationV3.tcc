/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV3.hpp"
#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

template<class T>
LoadConfigurationV3::LoadConfigurationV3(const details::load_configuration_v3<T>& header) :
  LoadConfigurationV2{reinterpret_cast<const details::load_configuration_v2<T>&>(header)},
  guard_address_taken_iat_entry_table_{header.GuardAddressTakenIatEntryTable},
  guard_address_taken_iat_entry_count_{header.GuardAddressTakenIatEntryCount},
  guard_long_jump_target_table_{header.GuardLongJumpTargetTable},
  guard_long_jump_target_count_{header.GuardLongJumpTargetCount}
{
}


} // namespace PE
} // namespace LIEF

