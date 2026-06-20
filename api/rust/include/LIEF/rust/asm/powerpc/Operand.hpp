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
#include "LIEF/asm/powerpc/Operand.hpp"

#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"

class asm_powerpc_Operand : public Mirror<LIEF::assembly::powerpc::Operand> {
  public:
  using lief_t = LIEF::assembly::powerpc::Operand;
  using Mirror::Mirror;

  auto to_string() const {
    return to_unique_string(get().to_string());
  }
};
