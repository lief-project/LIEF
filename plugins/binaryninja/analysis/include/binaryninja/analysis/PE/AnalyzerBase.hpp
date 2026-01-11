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
#include "binaryninja/analysis/PE/TypeBuilder.hpp"

namespace LIEF::PE {
class Binary;
}
namespace BinaryNinja {
class BinaryView;
class Structure;
}

namespace analysis_plugin::pe {
class AnalyzerBase : public analysis_plugin::AnalyzerBase {
  public:
  static constexpr auto DEFAULT_TYPE_SRC = "lief-pe";
  AnalyzerBase() = delete;
  AnalyzerBase(BinaryNinja::BinaryView& bv, LIEF::PE::Binary& pe,
               TypeBuilder& type_builder) :
    analysis_plugin::AnalyzerBase(bv), pe_(pe), type_builder_(type_builder)
  {}

  ~AnalyzerBase() override = default;

  uint64_t get_va(uint64_t rva) const;
  uint64_t translate_addr(uint64_t addr) const;

  protected:
  LIEF::PE::Binary& pe_;
  TypeBuilder& type_builder_;
};
}
