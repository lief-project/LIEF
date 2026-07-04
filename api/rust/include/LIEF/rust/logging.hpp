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
#include "LIEF/logging.hpp"
#include "LIEF/rust/helpers.hpp"
#include <cstdint>
#include <memory>

class LIEF_Logging {
  public:
  static auto disable() {
    LIEF::logging::disable();
  }
  static auto reset() {
    LIEF::logging::reset();
  }
  static auto enable() {
    LIEF::logging::enable();
  }
  static auto set_level(uint32_t lvl) {
    LIEF::logging::set_level(LIEF::logging::LEVEL(lvl));
  }
  static auto set_path(const std::string& path) {
    LIEF::logging::set_path(path);
  }

  static auto log(uint32_t lvl, const std::string& msg) {
    LIEF::logging::log(LIEF::logging::LEVEL(lvl), msg);
  }

  static auto get_level() {
    return as_u32(LIEF::logging::get_level());
  }
};

class LIEF_Logging_Scoped {
  public:
  LIEF_Logging_Scoped() = delete;
  LIEF_Logging_Scoped(const LIEF_Logging_Scoped&) = delete;
  LIEF_Logging_Scoped& operator=(const LIEF_Logging_Scoped&) = delete;

  static auto create(uint32_t lvl) {
    return std::unique_ptr<LIEF_Logging_Scoped>(new LIEF_Logging_Scoped(lvl));
  }

  auto set_level(uint32_t lvl) const {
    scoped_.set_level(LIEF::logging::LEVEL(lvl));
  }

  auto reset() {
    scoped_.reset();
  }

  ~LIEF_Logging_Scoped() = default;

  private:
  explicit LIEF_Logging_Scoped(uint32_t lvl) :
    scoped_(LIEF::logging::LEVEL(lvl)) {}

  LIEF::logging::Scoped scoped_{LIEF::logging::LEVEL::INFO};
};
