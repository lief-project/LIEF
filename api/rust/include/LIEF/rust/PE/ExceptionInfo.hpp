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

#include "LIEF/PE/ExceptionInfo.hpp"
#include "LIEF/rust/Mirror.hpp"

class PE_ExceptionInfo : public Mirror<LIEF::PE::ExceptionInfo> {
  public:
  using lief_t = LIEF::PE::ExceptionInfo;
  using Mirror::Mirror;

  auto rva_start() const {
    return get().rva_start();
  }

  std::string to_string() const {
    return get().to_string();
  }
};
