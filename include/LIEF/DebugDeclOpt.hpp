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
#ifndef LIEF_DEBUG_DECL_OPT_H
#define LIEF_DEBUG_DECL_OPT_H
#include <cstdint>

namespace LIEF {

/// Configuration options for generated code from debug info.
///
/// This structure configures how the debug information (DWARF/PDB) translated
/// into an AST is generated.
struct DeclOpt {
  /// The number of spaces for indentation.
  uint32_t indentation = 2;

  /// Prefer C++ syntax over C syntax.
  ///
  /// If true, the output will use C++ features (e.g., `bool` keyword)
  bool is_cpp = false;

  /// Enable extended comments and annotations.
  ///
  /// If true, the generated code will include comments containing low-level
  /// details such as memory addresses, offsets, type sizes, and original
  /// source locations.
  bool show_extended_annotations = true;

  /// Include full type definitions.
  ///
  /// If true, the output will contain the full definition of types (structs,
  /// enums, unions).
  bool include_types = false;

  /// Resolve type aliases (sugar).
  ///
  /// If true, `typedef`s and type aliases are replaced by their underlying
  /// canonical types (e.g., `uint32_t` might become `unsigned int`).
  bool desugar = true;
};

}
#endif
