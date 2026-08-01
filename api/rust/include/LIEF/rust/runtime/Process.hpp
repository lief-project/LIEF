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

#include "LIEF/runtime/Process.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"

class runtime_Process : private Mirror<LIEF::runtime::Process> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::runtime::Process;

  static int32_t pid() {
    return lief_t::pid();
  }

  static int32_t tid() {
    return lief_t::tid();
  }

  static auto platform() {
    return as_u32(lief_t::platform());
  }

  static auto arch() {
    return as_u32(lief_t::arch());
  }

  static auto page_size() {
    return lief_t::page_size();
  }
};
