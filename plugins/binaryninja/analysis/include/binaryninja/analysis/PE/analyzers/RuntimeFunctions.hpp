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

#include "binaryninja/analysis/PE/AnalyzerBase.hpp"

#include "LIEF/PE/ExceptionInfo.hpp"
#include "LIEF/PE/exceptions_info/RuntimeFunctionX64.hpp"
#include "LIEF/PE/exceptions_info/RuntimeFunctionAArch64.hpp"

namespace analysis_plugin::pe::analyzers {
class RuntimeFunctions : public AnalyzerBase {
  public:
  using AnalyzerBase::AnalyzerBase;
  static bool can_run(BinaryNinja::BinaryView& bv, LIEF::PE::Binary& pe);

  void run() override;

  ~RuntimeFunctions() override = default;

  static BinaryNinja::Ref<BinaryNinja::Platform> windows_x64() {
    static auto PLATFORM = BinaryNinja::Platform::GetByName("windows-x86_64");
    return PLATFORM;
  }

  static BinaryNinja::Ref<BinaryNinja::Platform> windows_arm64() {
    static auto PLATFORM = BinaryNinja::Platform::GetByName("windows-aarch64");
    return PLATFORM;
  }

  private:
  void process(const LIEF::PE::RuntimeFunctionX64& x64);
  void process(const LIEF::PE::RuntimeFunctionAArch64& arm64);

};

}
