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

#include <cstdint>
#include <memory>

#include "LIEF/runtime/disassembler.hpp"
#include "LIEF/rust/Iterator.hpp"
#include "LIEF/rust/asm/Instruction.hpp"

class runtime_it_instructions
  : public ForwardIterator<asm_Instruction,
                           LIEF::assembly::Instruction::Iterator> {
  public:
  runtime_it_instructions(uint64_t addr) :
    ForwardIterator(LIEF::runtime::disassemble(static_cast<uintptr_t>(addr))) {}

  auto next() {
    return ForwardIterator::next();
  }
};

inline auto runtime_disassemble(uint64_t addr) {
  return std::make_unique<runtime_it_instructions>(addr);
}
