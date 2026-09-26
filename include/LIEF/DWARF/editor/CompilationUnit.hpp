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
#ifndef LIEF_DWARF_EDITOR_COMPILATION_UNIT_H
#define LIEF_DWARF_EDITOR_COMPILATION_UNIT_H
#include <string_view>
#include <memory>

#include "LIEF/compiler_attributes.hpp"
#include "LIEF/visibility.h"

#include "LIEF/DWARF/editor/BaseType.hpp"
#include "LIEF/DWARF/editor/FunctionType.hpp"
#include "LIEF/DWARF/editor/PointerType.hpp"
#include "LIEF/DWARF/editor/StructType.hpp"


namespace LIEF::dwarf::editor {
class Function;
class Variable;
class Type;
class EnumType;
class TypeDef;
class ArrayType;

namespace details {
class CompilationUnit;
}

/// This class represents an **editable** DWARF compilation unit
class LIEF_API CompilationUnit {
  public:
  CompilationUnit() = delete;
  CompilationUnit(std::unique_ptr<details::CompilationUnit> impl);

  /// Set the `DW_AT_producer` producer attribute.
  ///
  /// This attribute aims to inform about the program that generated this
  /// compilation unit (e.g. `LIEF Extended`)
  CompilationUnit& set_producer(std::string_view producer) LIEF_LIFETIMEBOUND;

  /// Create a new function owned by this compilation unit
  std::unique_ptr<Function>
      create_function(std::string_view name) LIEF_LIFETIMEBOUND;

  /// Create a new **global** variable owned by this compilation unit
  std::unique_ptr<Variable>
      create_variable(std::string_view name) LIEF_LIFETIMEBOUND;

  /// Create a `DW_TAG_unspecified_type` type with the given name
  std::unique_ptr<Type>
      create_generic_type(std::string_view name) LIEF_LIFETIMEBOUND;

  /// Create an enum type (`DW_TAG_enumeration_type`)
  std::unique_ptr<EnumType> create_enum(std::string_view name) LIEF_LIFETIMEBOUND;

  /// Create a typedef with the name provided in the first parameter which aliases
  /// the type provided in the second parameter
  std::unique_ptr<TypeDef> create_typedef(std::string_view name,
                                          const Type& type) LIEF_LIFETIMEBOUND;

  /// Create a struct-like type (struct, class, union) with the given name.
  std::unique_ptr<StructType> create_structure(
      std::string_view name, StructType::TYPE kind = StructType::TYPE::STRUCT
  ) LIEF_LIFETIMEBOUND;

  /// Create a primitive type with the given name and size.
  std::unique_ptr<BaseType> create_base_type(
      std::string_view name, size_t size,
      BaseType::ENCODING encoding = BaseType::ENCODING::NONE
  ) LIEF_LIFETIMEBOUND;

  /// Create a function type with the given name.
  std::unique_ptr<FunctionType>
      create_function_type(std::string_view name) LIEF_LIFETIMEBOUND;

  /// Create a pointer on the provided type
  std::unique_ptr<PointerType>
      create_pointer_type(const Type& ty) LIEF_LIFETIMEBOUND {
    return ty.pointer_to();
  }

  /// Create a `const`-qualified version of the provided type
  /// (`DW_TAG_const_type`).
  ///
  /// Qualifying the same type twice returns the same underlying DWARF entry.
  std::unique_ptr<Type> create_const_type(const Type& ty) LIEF_LIFETIMEBOUND;

  /// Create a `volatile`-qualified version of the provided type
  /// (`DW_TAG_volatile_type`).
  ///
  /// Qualifying the same type twice returns the same underlying DWARF entry.
  std::unique_ptr<Type> create_volatile_type(const Type& ty) LIEF_LIFETIMEBOUND;

  /// Create a `void` type
  std::unique_ptr<Type> create_void_type() LIEF_LIFETIMEBOUND;

  /// Create an array type with the given name, type and size.
  std::unique_ptr<ArrayType> create_array(std::string_view name, const Type& type,
                                          size_t count) LIEF_LIFETIMEBOUND;

  ~CompilationUnit();

  private:
  std::unique_ptr<details::CompilationUnit> impl_;
};

}


#endif
