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
#include "PE/Structures.hpp"
#include "LIEF/PE/LoadConfigurations/LoadConfigurationV6.hpp"

namespace LIEF {
namespace PE {

template<class T>
LoadConfigurationV6::LoadConfigurationV6(const details::load_configuration_v6<T>& header) :
  LoadConfigurationV5{reinterpret_cast<const details::load_configuration_v5<T>&>(header)},
  guardrf_verify_stackpointer_function_pointer_{header.GuardRFVerifyStackPointerFunctionPointer},
  hotpatch_table_offset_{header.HotPatchTableOffset}
{}


} // namespace PE
} // namespace LIEF

