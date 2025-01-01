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
#include <LIEF/asm/aarch64/Instruction.hpp>

#include "LIEF/rust/asm/Instruction.hpp"
#include "LIEF/rust/asm/aarch64/Operand.hpp"

#include "LIEF/rust/helpers.hpp"
#include "LIEF/rust/Iterator.hpp"

class asm_aarch64_Instruction : public asm_Instruction {
  public:
  using lief_t = LIEF::assembly::aarch64::Instruction;

  class it_operands :
      public ForwardIterator<asm_aarch64_Operand, LIEF::assembly::aarch64::Operand::Iterator>
  {
    public:
    it_operands(const asm_aarch64_Instruction::lief_t& src)
      : ForwardIterator(src.operands()) { }

    auto next() { return ForwardIterator::next(); }
  };

  uint64_t opcode() const {
    return to_int(impl().opcode());
  }
  auto operands() const {
    return std::make_unique<it_operands>(impl());
  }

  static bool classof(const asm_Instruction& inst) {
    return lief_t::classof(&inst.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
