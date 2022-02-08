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

#include "LIEF/PE/LoadConfigurations/LoadConfigurationV1.hpp"
#include "PE/Structures.hpp"
namespace LIEF {
namespace PE {

template<class T>
LoadConfigurationV1::LoadConfigurationV1(const details::load_configuration_v1<T>& header) :
  LoadConfigurationV0{reinterpret_cast<const details::load_configuration_v0<T>&>(header)},
  guard_cf_check_function_pointer_{header.GuardCFCheckFunctionPointer},
  guard_cf_dispatch_function_pointer_{header.GuardCFDispatchFunctionPointer},
  guard_cf_function_table_{header.GuardCFFunctionTable},
  guard_cf_function_count_{header.GuardCFFunctionCount},
  guard_flags_{static_cast<GUARD_CF_FLAGS>(header.GuardFlags)}
{
}


} // namespace PE
} // namespace LIEF

