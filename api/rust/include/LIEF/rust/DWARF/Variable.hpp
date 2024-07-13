/* Copyright 2022 - 2024 R. Thomas
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
#include "LIEF/DWARF/Variable.hpp"
#include "LIEF/rust/DWARF/Type.hpp"
#include "LIEF/rust/DWARF/Scope.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/error.hpp"
#include "LIEF/rust/debug_location.hpp"

class DWARF_Variable : private Mirror<LIEF::dwarf::Variable> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::dwarf::Variable;

  auto name() const { return get().name(); }
  auto linkage_name() const { return get().linkage_name(); }

  int64_t address(uint32_t& err) const {
    return details::make_error<int64_t>(get().address(), err);
  }

  uint64_t size(uint32_t& err) const {
    return details::make_error<uint64_t>(get().size(), err);
  }

  auto debug_location() const {
    return details::make_location(get().debug_location());
  }

  auto is_constexpr() const {
    return get().is_constexpr();
  }

  auto get_type() const {
    return details::try_unique<DWARF_Type>(get().type()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto scope() const {
    return details::try_unique<DWARF_Scope>(get().scope());
  }
};
