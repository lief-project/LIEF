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

#include "binaryninja/analysis/ELF/AnalyzerBase.hpp"

namespace binaryninja {
class BNStream;
}

namespace analysis_plugin::elf::analyzers {
class Relocations : public AnalyzerBase {
  public:
  using AnalyzerBase::AnalyzerBase;
  static bool can_run(BinaryNinja::BinaryView& bv, LIEF::ELF::Binary& elf);

  void run() override;

  ~Relocations() override = default;
};

}
