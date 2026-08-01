/* Copyright 2022 - 2026 R. Thomas
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

#include "LIEF/runtime/osx/Process.hpp"
#include "LIEF/rust/helpers.hpp"

class runtime_osx_Process {
  public:
  using lief_t = LIEF::runtime::osx::Process;

  static auto dyld_version() {
    return to_unique_string(lief_t::dyld_version());
  }
};
