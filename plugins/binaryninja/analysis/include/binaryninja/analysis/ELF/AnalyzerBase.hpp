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

#include "binaryninja/analysis/AnalyzerBase.hpp"
#include "binaryninja/analysis/ELF/TypeBuilder.hpp"

namespace LIEF::ELF {
class Binary;
class Relocation;
}
namespace BinaryNinja {
class BinaryView;
class Structure;
}

namespace analysis_plugin::elf {
class AnalyzerBase : public analysis_plugin::AnalyzerBase {
  public:
  static constexpr auto DEFAULT_TYPE_SRC = "lief-elf";
  AnalyzerBase(BinaryNinja::BinaryView& bv, LIEF::ELF::Binary& elf,
               TypeBuilder& type_builder);
  AnalyzerBase() = delete;


  ~AnalyzerBase() override = default;

  uint64_t translate_addr(uint64_t addr, bool revert = false) const;
  bool apply_relocation(const LIEF::ELF::Relocation& R);
  virtual void define_relocated_type(const LIEF::ELF::Relocation& R, uint64_t target);

  protected:
  LIEF::ELF::Binary& elf_;
  TypeBuilder& type_builder_;
  uint64_t default_image_base_ = 0;
  uint64_t default_virtual_size = 0;
};
}
