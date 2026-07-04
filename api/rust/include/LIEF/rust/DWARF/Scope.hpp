/* Copyright 2022 - 2026 R. Thomas
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
#include "LIEF/DWARF/Scope.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"

class DWARF_Scope : private Mirror<LIEF::dwarf::Scope> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::dwarf::Scope;

  auto name() const {
    return to_unique_string(get().name());
  }
  auto parent() const {
    return details::try_unique<DWARF_Scope>(get().parent());
  }
  auto get_type() const {
    return as_u32(get().type());
  }
  auto chained(const std::string& sep) const {
    return to_unique_string(get().chained(sep));
  }
};
