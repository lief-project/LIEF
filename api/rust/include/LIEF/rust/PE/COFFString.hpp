/* Copyright 2024 - 2025 R. Thomas
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

#include "LIEF/PE/COFFString.hpp"
#include "LIEF/rust/Mirror.hpp"

class PE_COFFString : public Mirror<LIEF::PE::COFFString> {
  public:
  using lief_t = LIEF::PE::COFFString;
  using Mirror::Mirror;

  std::string str() const {
    return get().str();
  }

  auto offset() const {
    return get().offset();
  }
};
