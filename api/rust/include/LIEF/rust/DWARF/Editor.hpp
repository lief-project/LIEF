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
#include <LIEF/DWARF/Editor.hpp>
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/DWARF/editor/CompilationUnit.hpp"
#include "LIEF/rust/Abstract/Binary.hpp"

class DWARF_Editor : public Mirror<LIEF::dwarf::Editor> {
  public:
  using lief_t = LIEF::dwarf::Editor;
  using Mirror::Mirror;

  auto create_compilation_unit() {
    return details::try_unique<DWARF_editor_CompilationUnit>(get().create_compilation_unit());
  }

  auto write(std::string output) {
    get().write(output);
  }

  static auto from_binary(AbstractBinary& bin) {
    return details::try_unique<DWARF_Editor>(lief_t::from_binary(bin.get()));
  }

  static auto create(uint32_t fmt, uint32_t arch) {
    return details::try_unique<DWARF_Editor>(lief_t::create((lief_t::FORMAT)fmt, (lief_t::ARCH)arch));
  }
};
