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
#include "LIEF/DWARF/Type.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/DWARF/Scope.hpp"
#include "LIEF/rust/error.hpp"
#include "LIEF/rust/debug_location.hpp"

class DWARF_Type : public Mirror<LIEF::dwarf::Type> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::dwarf::Type;

  std::string name(uint32_t& err) const {
    return details::make_error(get().name(), err);
  }

  uint64_t size(uint32_t& err) const {
    return details::make_error(get().size(), err);
  }

  auto location() const {
    return details::make_location(get().location());
  }

  auto is_unspecified() const {
    return get().is_unspecified();
  }

  auto scope() const {
    return details::try_unique<DWARF_Scope>(get().scope()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }
};
