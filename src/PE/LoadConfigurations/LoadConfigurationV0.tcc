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

namespace LIEF {
namespace PE {

template <class T>
LoadConfigurationV0::LoadConfigurationV0(
    const details::load_configuration_v0<T>& header)
    : LoadConfiguration{reinterpret_cast<const details::load_configuration<T>&>(
          header)},
      se_handler_table_{header.SEHandlerTable},
      se_handler_count_{header.SEHandlerCount} {}

}  // namespace PE
}  // namespace LIEF
