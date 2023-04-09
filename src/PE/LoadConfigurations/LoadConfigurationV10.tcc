/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
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
namespace LIEF {
namespace PE {

template<class T>
LoadConfigurationV10::LoadConfigurationV10(const details::load_configuration_v10<T>& header) :
  LoadConfigurationV9{static_cast<const details::load_configuration_v9<T>&>(header)},
  guard_xfg_check_function_pointer_{header.GuardXFGCheckFunctionPointer},
  guard_xfg_dispatch_function_pointer_{header.GuardXFGDispatchFunctionPointer},
  guard_xfg_table_dispatch_function_pointer_{header.GuardXFGTableDispatchFunctionPointer}
{
}


} // namespace PE
} // namespace LIEF

