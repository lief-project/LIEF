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
#include <cstdint>
#include <string>

#include "LIEF/PE/resources/ResourceAccelerator.hpp"
#include "LIEF/rust/Mirror.hpp"

class PE_ResourceAccelerator : private Mirror<LIEF::PE::ResourceAccelerator> {
  public:
  using lief_t = LIEF::PE::ResourceAccelerator;
  using Mirror::Mirror;

  auto flags() const {
    return get().flags();
  }
  auto ansi() const {
    return get().ansi();
  }
  auto id() const {
    return get().id();
  }
  auto padding() const {
    return get().padding();
  }

  std::string ansi_str() const {
    return get().ansi_str();
  }
};
