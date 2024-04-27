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

#pragma once

#include "LIEF/MachO/ExportInfo.hpp"
#include "LIEF/rust/MachO/Symbol.hpp"
#include "LIEF/rust/MachO/Dylib.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"

class MachO_ExportInfo : private Mirror<LIEF::MachO::ExportInfo> {
  public:
  using lief_t = LIEF::MachO::ExportInfo;
  using Mirror::Mirror;

  uint64_t node_offset() const { return get().node_offset(); };
  uint64_t flags() const { return get().flags(); };
  uint64_t address() const { return get().address(); };
  uint64_t other() const { return get().other(); };
  auto kind() const { return to_int(get().kind()); };

  auto symbol() const {
    return details::try_unique<MachO_Symbol>(get().symbol());
  }

  auto alias() const {
    return details::try_unique<MachO_Symbol>(get().alias());
  }

  auto alias_library() const {
    return details::try_unique<MachO_Dylib>(get().alias_library());
  }
};
