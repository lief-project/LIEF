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
#include "LIEF/DWARF/editor/EnumType.hpp"
#include "LIEF/rust/DWARF/editor/Type.hpp"


class DWARF_editor_EnumType_Value : public Mirror<LIEF::dwarf::editor::EnumType::Value> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::dwarf::editor::EnumType::Value;
};

class DWARF_editor_EnumType : public DWARF_editor_Type {
  public:
  using DWARF_editor_Type::DWARF_editor_Type;
  using lief_t = LIEF::dwarf::editor::EnumType;

  auto set_size(uint64_t size) {
    impl().set_size(size);
  }

  auto add_value(std::string name, int64_t value) {
    return details::try_unique<DWARF_editor_EnumType_Value>(
      impl().add_value(name, value)
    );
  }

  auto set_underlying_type(const DWARF_editor_Type& ty) {
    impl().set_underlying_type(ty.get());
  }

  static bool classof(const DWARF_editor_Type& type) {
    return lief_t::classof(&type.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
  lief_t& impl() { return as<lief_t>(this); }
};
