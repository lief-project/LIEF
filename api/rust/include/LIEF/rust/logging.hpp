/* Copyright 2024 R. Thomas
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
#include <cstdint>

class LIEF_Logging {
  public:
  static void disable() { LIEF::logging::disable(); }
  static void reset() { LIEF::logging::reset(); }
  static void enable() { LIEF::logging::enable(); }
  static void set_level(uint32_t lvl) {
    LIEF::logging::set_level(LIEF::logging::LEVEL(lvl));
  }
  static void set_path(std::string path) { // NOLINT
    LIEF::logging::set_path(path);
  }

  static void log(uint32_t lvl, std::string msg) { // NOLINT
    LIEF::logging::log(LIEF::logging::LEVEL(lvl), msg);
  }
};
