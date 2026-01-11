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
#include <unordered_map>
#include <LIEF/DWARF/editor/CompilationUnit.hpp>
#include <binaryninja/binaryninjaapi.h>

namespace dwarf_plugin {
class TypeEngine {
  public:
  // We using BinaryNinja::Type::GetString(...) as key for the map since
  // it provides a better unicity for the types already added.
  // (Previously BinaryNinja::Type::GetObject())
  using type_map_t = std::unordered_map<
    std::string, std::unique_ptr<LIEF::dwarf::editor::Type>>;

  using anon_types_t = std::vector<
    std::unique_ptr<LIEF::dwarf::editor::Type>>;

  TypeEngine() = delete;
  TypeEngine(LIEF::dwarf::editor::CompilationUnit& CU,
             BinaryNinja::BinaryView& bv) :
    unit_(CU), bv_(bv)
  {}

  static std::unique_ptr<TypeEngine> create(
      LIEF::dwarf::editor::CompilationUnit& CU, BinaryNinja::BinaryView& bv) {
    auto engine = std::make_unique<TypeEngine>(CU, bv);
    engine->init();
    return engine;
  }

  LIEF::dwarf::editor::Type& add_type(const BinaryNinja::Type& type);

  private:
  void init();

  void add_member(
    const BinaryNinja::StructureMember& member,
    LIEF::dwarf::editor::StructType& S);

  size_t id_ = 0;
  size_t array_id_ = 0;
  size_t func_id_ = 0;
  type_map_t mapping_;
  anon_types_t anon_types_;
  LIEF::dwarf::editor::CompilationUnit& unit_;
  BinaryNinja::BinaryView& bv_;
};
}

