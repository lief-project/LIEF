/* Copyright 2022 - 2024 R. Thomas
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
#include "LIEF/debug_loc.hpp"
#include <memory>

class DebugLocation {
  public:
  DebugLocation(std::string file, uint64_t line) :
    line_(line),
    file_(std::move(file))
  {}

  auto file() const { return file_; }
  auto line() const { return line_; }

  private:
  uint64_t line_ = 0;
  std::string file_;
};

namespace details {
inline auto make_location(const LIEF::debug_location_t& loc) {
  return std::make_unique<DebugLocation>(loc.file, loc.line);
}
}

