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
#include "LIEF/asm/Instruction.hpp"
#include "LIEF/rust/Span.hpp"

#include "LIEF/rust/Mirror.hpp"


class asm_Instruction : private Mirror<LIEF::assembly::Instruction> {
  public:
  using lief_t = LIEF::assembly::Instruction;
  using Mirror::Mirror;


  auto address() const { return get().address(); }

  uint64_t size() const { return get().size(); }

  auto raw() const { return  make_span(get().raw()); }

  auto mnemonic() const { return get().mnemonic(); }

  auto to_string() const { return get().to_string(); }

};
