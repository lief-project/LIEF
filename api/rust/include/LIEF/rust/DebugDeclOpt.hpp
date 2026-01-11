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
#include <memory>
#include <LIEF/DebugDeclOpt.hpp>

class LIEF_DeclOpt {
  public:
  static auto create() {
    return std::make_unique<LIEF_DeclOpt>();
  }

  const LIEF::DeclOpt& conf() const {
    return config_;
  }

  void set_indentation(uint32_t value) {
    config_.indentation = value;
  }

  void set_is_cpp(bool value) {
    config_.is_cpp = value;
  }

  void set_show_extended_annotations(bool value) {
    config_.show_extended_annotations = value;
  }

  void set_include_types(bool value) {
    config_.include_types = value;
  }

  void set_desugar(bool value) {
    config_.desugar = value;
  }

  private:
  LIEF::DeclOpt config_;
};
