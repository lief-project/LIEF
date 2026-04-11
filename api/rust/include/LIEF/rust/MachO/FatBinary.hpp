/* Copyright 2024 - 2026 R. Thomas
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
#include <LIEF/MachO.hpp>
#include "LIEF/rust/MachO/Binary.hpp"
#include "LIEF/rust/Mirror.hpp"

class MachO_ParserConfig {
  public:
  static auto create() {
    return std::make_unique<MachO_ParserConfig>();
  }

  const LIEF::MachO::ParserConfig& conf() const {
    return config_;
  }

  void set_parse_dyld_exports(bool value) {
    config_.parse_dyld_exports = value;
  }

  void set_parse_dyld_bindings(bool value) {
    config_.parse_dyld_bindings = value;
  }

  void set_parse_dyld_rebases(bool value) {
    config_.parse_dyld_rebases = value;
  }

  void set_parse_overlay(bool value) {
    config_.parse_overlay = value;
  }

  void set_fix_from_memory(bool value) {
    config_.fix_from_memory = value;
  }

  void set_from_dyld_shared_cache(bool value) {
    config_.from_dyld_shared_cache = value;
  }

  private:
  LIEF::MachO::ParserConfig config_ = LIEF::MachO::ParserConfig::deep();
};

class MachO_FatBinary : public Mirror<LIEF::MachO::FatBinary> {
  public:
  using Mirror::Mirror;
  static auto parse(std::string path) {
    return details::try_unique<MachO_FatBinary>(LIEF::MachO::Parser::parse(path));
  }

  static auto parse_with_config(
      std::string path, const MachO_ParserConfig& config
  ) { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<MachO_FatBinary>(
        LIEF::MachO::Parser::parse(path, config.conf())
    );
  }

  uint32_t size() const {
    return get().size();
  }

  std::unique_ptr<MachO_Binary> binary_at(uint32_t index) const {
    if (auto* bin = get().at(index)) {
      return std::make_unique<MachO_Binary>(*bin);
    }
    return nullptr;
  }

  std::unique_ptr<MachO_Binary> binary_from_arch(int32_t cpu) const {
    if (auto* bin = get().get((LIEF::MachO::Header::CPU_TYPE)cpu)) {
      return std::make_unique<MachO_Binary>(*bin);
    }
    return nullptr;
  }

  void write(std::string output) {
    impl().write(output);
  }

  private:
  LIEF::MachO::FatBinary& impl() {
    return const_cast<LIEF::MachO::FatBinary&>(get());
  }
};
