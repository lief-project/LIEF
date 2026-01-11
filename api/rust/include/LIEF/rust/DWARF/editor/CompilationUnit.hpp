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
#include <LIEF/DWARF/editor/CompilationUnit.hpp>
#include "LIEF/rust/Mirror.hpp"

#include "LIEF/rust/DWARF/editor/Function.hpp"
#include "LIEF/rust/DWARF/editor/Variable.hpp"
#include "LIEF/rust/DWARF/editor/Type.hpp"
#include "LIEF/rust/DWARF/editor/EnumType.hpp"
#include "LIEF/rust/DWARF/editor/TypeDef.hpp"
#include "LIEF/rust/DWARF/editor/StructType.hpp"
#include "LIEF/rust/DWARF/editor/BaseType.hpp"
#include "LIEF/rust/DWARF/editor/FunctionType.hpp"
#include "LIEF/rust/DWARF/editor/PointerType.hpp"
#include "LIEF/rust/DWARF/editor/ArrayType.hpp"

class DWARF_editor_CompilationUnit : public Mirror<LIEF::dwarf::editor::CompilationUnit> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::dwarf::editor::CompilationUnit;

  auto set_producer(std::string value) {
    get().set_producer(value);
  }

  auto create_function(std::string name) {
    return details::try_unique<DWARF_editor_Function>(get().create_function(name));
  }

  auto create_variable(std::string name) {
    return details::try_unique<DWARF_editor_Variable>(get().create_variable(name));
  }

  auto create_generic_type(std::string name) {
    return details::try_unique<DWARF_editor_Type>(get().create_generic_type(name));
  }

  auto create_enum(std::string name) {
    return details::try_unique<DWARF_editor_EnumType>(get().create_enum(name));
  }

  auto create_typedef(std::string name, const DWARF_editor_Type& ty) {
    return details::try_unique<DWARF_editor_TypeDef>(get().create_typedef(name, ty.get()));
  }

  auto create_structure(std::string name, uint32_t kind) {
    return details::try_unique<DWARF_editor_StructType>(
      get().create_structure(name, (LIEF::dwarf::editor::StructType::TYPE)kind)
    );
  }

  auto create_base_type(std::string name, uint64_t size, uint32_t encoding) {
    return details::try_unique<DWARF_editor_BaseType>(
      get().create_base_type(name, size, (LIEF::dwarf::editor::BaseType::ENCODING)encoding)
    );
  }

  auto create_function_type(std::string name) {
    return details::try_unique<DWARF_editor_FunctionType>(
      get().create_function_type(name)
    );
  }

  auto create_pointer_type(const DWARF_editor_Type& ty) {
    return details::try_unique<DWARF_editor_PointerType>(
      get().create_pointer_type(ty.get())
    );
  }

  auto create_void_type() {
    return details::try_unique<DWARF_editor_Type>(
      get().create_void_type()
    );
  }

  auto create_array_type(std::string name, const DWARF_editor_Type& ty, uint64_t count) {
    return details::try_unique<DWARF_editor_ArrayType>(
      get().create_array(name, ty.get(), count)
    );
  }
};
