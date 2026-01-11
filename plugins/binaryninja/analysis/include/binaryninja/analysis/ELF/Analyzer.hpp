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
#include <memory>
#include <vector>

#include "binaryninja/analysis/Analyzer.hpp"

#include "binaryninja/analysis/ELF/AnalyzerBase.hpp"

#include "LIEF/ELF.hpp"

namespace analysis_plugin::elf {
class Analyzer : public analysis_plugin::Analyzer {
  public:
  using analyzers_t = std::vector<std::unique_ptr<AnalyzerBase>>;

  Analyzer() = delete;
  Analyzer(std::unique_ptr<LIEF::ELF::Binary> impl, BinaryNinja::BinaryView& bv);

  void run() override;

  static std::unique_ptr<Analyzer> from_bv(BinaryNinja::BinaryView& bv);

  template<class T>
  std::unique_ptr<T> instantiate() {
    return std::make_unique<T>(*bv_, *elf_, static_cast<elf::TypeBuilder&>(*type_builder_));
  }

  ~Analyzer() override = default;

  protected:
  std::unique_ptr<LIEF::ELF::Binary> elf_;
  analyzers_t analyzers_;
};
}
