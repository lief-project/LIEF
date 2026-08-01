/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
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
#ifndef LIEF_PE_AUXILIARY_FILE_H
#define LIEF_PE_AUXILIARY_FILE_H

#include <string_view>
#include <memory>

#include "LIEF/COFF/AuxiliarySymbol.hpp"
#include "LIEF/compiler_attributes.hpp"
#include "LIEF/visibility.h"


namespace LIEF::COFF {

/// This auxiliary symbol represents a filename (auxiliary format 4)
///
/// The Symbol::name itself should start with `.file`, and this auxiliary record
/// gives the name of a source-code file.
///
/// Reference:
/// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#auxiliary-format-4-files
class LIEF_API AuxiliaryFile : public AuxiliarySymbol {
  public:
  LIEF_LOCAL static std::unique_ptr<AuxiliaryFile>
      parse(const std::vector<uint8_t>& payload);

  AuxiliaryFile() :
    AuxiliarySymbol(AuxiliarySymbol::TYPE::FILE) {}

  AuxiliaryFile(std::string file) :
    AuxiliarySymbol(AuxiliarySymbol::TYPE::FILE),
    filename_(std::move(file)) {}

  AuxiliaryFile(const AuxiliaryFile&) = default;
  AuxiliaryFile& operator=(const AuxiliaryFile&) = default;

  AuxiliaryFile(AuxiliaryFile&&) = default;
  AuxiliaryFile& operator=(AuxiliaryFile&&) = default;

  std::unique_ptr<AuxiliarySymbol> clone() const override {
    return std::make_unique<AuxiliaryFile>(*this);
  }

  /// The associated filename
  std::string_view filename() const LIEF_LIFETIMEBOUND {
    return filename_;
  }

  AuxiliaryFile& filename(std::string file) {
    filename_ = std::move(file);
    return *this;
  }

  std::string to_string() const override {
    std::string out = "AuxiliaryFile {\n";
    out += "  " + filename_ + "\n}";
    return out;
  }

  ~AuxiliaryFile() override = default;

  static bool classof(const AuxiliarySymbol* sym) {
    return sym->type() == AuxiliarySymbol::TYPE::FILE;
  }

  protected:
  std::string filename_;
};

}

#endif
