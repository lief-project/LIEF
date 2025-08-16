/* Copyright 2025 R. Thomas
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

#include <cstdint>
#include <string>
#include <optional>

#include <binaryninjaapi.h>

namespace analysis_plugin {
class AnalyzerBase {
  public:
  AnalyzerBase() = delete;
  AnalyzerBase(BinaryNinja::BinaryView& bv) :
    bv_(bv)
  {}

  virtual void run() = 0;

  virtual ~AnalyzerBase() = default;

  void define_type_at(
      uint64_t address, BinaryNinja::Ref<BinaryNinja::Type> type,
      std::optional<std::string> name = std::nullopt,
      bool force = false);

  void define_struct_at(
      uint64_t address, BinaryNinja::Ref<BinaryNinja::Type> type,
      std::optional<std::string> name = std::nullopt,
      bool force = false);

  void define_struct_at(uint64_t address, const std::string& type,
                        std::optional<std::string> name = std::nullopt,
                        bool force = false);

  void define_array_at(uint64_t addr, BinaryNinja::Ref<BinaryNinja::Type> type,
                       size_t count, std::optional<std::string> name = std::nullopt,
                       bool force = false);

  void define_blob(uint64_t addr, size_t size,
      std::optional<std::string> name = std::nullopt, bool force = false);

  std::optional<BinaryNinja::DataVariable> get_defined_var(uint64_t addr);

  protected:
  BinaryNinja::BinaryView& bv_;
};
}
