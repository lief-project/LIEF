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

template<class T>
LoadConfigurationV7::LoadConfigurationV7(const details::load_configuration_v7<T>& header) :
  LoadConfigurationV6{reinterpret_cast<const details::load_configuration_v6<T>&>(header)},
  reserved3_{header.Reserved3},
  addressof_unicode_string_{header.AddressOfSomeUnicodeString}
{
}


} // namespace PE
} // namespace LIEF

