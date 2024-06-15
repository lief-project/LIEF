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
#include "LIEF/MachO/Header.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"

class MachO_Header : private Mirror<LIEF::MachO::Header> {
  public:
  using lief_t = LIEF::MachO::Header;
  using Mirror::Mirror;

  auto magic() const { return to_int(get().magic()); }
  int32_t cpu_type() const { return to_int(get().cpu_type()); }
  auto cpu_subtype() const { return get().cpu_subtype(); }
  auto file_type() const { return to_int(get().file_type()); }
  auto nb_cmds() const { return get().nb_cmds(); }
  auto sizeof_cmds() const { return get().sizeof_cmds(); }
  auto flags() const { return get().flags(); }
  auto reserved() const { return get().reserved(); }
};
