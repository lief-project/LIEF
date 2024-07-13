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
#include "LIEF/DWARF/types/Const.hpp"
#include "LIEF/rust/DWARF/Type.hpp"

class DWARF_types_Const : public DWARF_Type {
  public:
  using lief_t = LIEF::dwarf::types::Const;

  static bool classof(const DWARF_Type& type) {
    return lief_t::classof(&type.get());
  }

  auto underlying_type() const {
    return details::try_unique<DWARF_Type>(impl().underlying_type()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
