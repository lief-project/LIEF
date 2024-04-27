/* Copyright 2024 R. Thomas
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

#include "LIEF/rust/MachO/Symbol.hpp"
#include "LIEF/rust/MachO/ExportInfo.hpp"
#include "LIEF/rust/MachO/BindingInfo.hpp"

std::unique_ptr<MachO_ExportInfo> MachO_Symbol::export_info() const {
  return details::try_unique<MachO_ExportInfo>(impl().export_info());
}

std::unique_ptr<MachO_BindingInfo> MachO_Symbol::binding_info() const {
  return details::try_unique<MachO_BindingInfo>(impl().binding_info());
}
