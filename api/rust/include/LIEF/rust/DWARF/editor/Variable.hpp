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
#include <LIEF/DWARF/editor/Variable.hpp>
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/DWARF/editor/Type.hpp"

class DWARF_editor_Variable : public Mirror<LIEF::dwarf::editor::Variable> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::dwarf::editor::Variable;

  auto set_external() { get().set_external(); }
  auto set_addr(uint64_t addr) { get().set_addr(addr); }
  auto set_stack_offset(uint64_t addr) { get().set_stack_offset(addr); }
  auto set_type(const DWARF_editor_Type& ty) { get().set_type(ty.get()); }

  auto add_description(std::string desc) { get().add_description(desc); }
};
