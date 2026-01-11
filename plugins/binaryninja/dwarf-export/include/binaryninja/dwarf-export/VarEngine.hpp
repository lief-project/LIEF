/* Copyright 2025 - 2026 R. Thomas
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
#include <LIEF/DWARF/editor/CompilationUnit.hpp>
#include <LIEF/DWARF/editor/Variable.hpp>

#include <binaryninjaapi.h>

namespace dwarf_plugin {
class TypeEngine;

class VarEngine {
  public:
  VarEngine() = delete;
  VarEngine(TypeEngine& types, LIEF::dwarf::editor::CompilationUnit& CU,
            BinaryNinja::BinaryView& bv) :
    types_(types), unit_(CU), bv_(bv)
  {}

  static std::unique_ptr<VarEngine> create(
      TypeEngine& types, LIEF::dwarf::editor::CompilationUnit& CU,
      BinaryNinja::BinaryView& bv)
  {
    auto engine = std::make_unique<VarEngine>(types, CU, bv);
    return engine;
  }

  LIEF::dwarf::editor::Variable* add_variable(const BinaryNinja::DataVariable& var);

  ~VarEngine() = default;

  private:
  TypeEngine& types_;
  LIEF::dwarf::editor::CompilationUnit& unit_;
  BinaryNinja::BinaryView& bv_;

  std::map<uint64_t, std::unique_ptr<LIEF::dwarf::editor::Variable>> vars_;
};
}

