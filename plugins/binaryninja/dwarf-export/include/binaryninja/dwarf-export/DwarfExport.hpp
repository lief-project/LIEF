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
#include <string>
#include <memory>

namespace BinaryNinja {
class BinaryView;
class Function;
class DataVariable;
}

namespace LIEF {
class Binary;
namespace dwarf {
class Editor;
namespace editor {
class CompilationUnit;
}
}
}

namespace dwarf_plugin {
class TypeEngine;

/// This class exposes the main API to export DWARF info
/// from a BinaryNinja's BinaryView instance
class DwarfExport {
  public:
  DwarfExport(BinaryNinja::BinaryView& bv);

  /// Instantiate a DWARF exporter for the given BinaryView object
  static std::unique_ptr<DwarfExport> from_bv(BinaryNinja::BinaryView& bv) {
    return std::make_unique<DwarfExport>(bv);
  }

  /// Create and cache a CompilationUnit object.
  LIEF::dwarf::editor::CompilationUnit* create();

  /// Save the generated DWARF file in the specified filename.
  ///
  /// The function returns the path where the dwarf is saved
  std::string save(const std::string& filename);

  /// Save the generated DWARF file next to the binary associated with
  /// the BinaryView object
  std::string save();

  ~DwarfExport();

  private:
  BinaryNinja::BinaryView* bv_ = nullptr;
  std::unique_ptr<LIEF::dwarf::editor::CompilationUnit> unit_;
  std::unique_ptr<LIEF::dwarf::Editor> editor_;
};
}
