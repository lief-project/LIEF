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
#ifndef LIEF_ASM_X86_INST_H
#define LIEF_ASM_X86_INST_H
#include "LIEF/compiler_attributes.hpp"
#include "LIEF/visibility.h"

#include "LIEF/asm/Instruction.hpp"
#include "LIEF/asm/x86/Operand.hpp"
#include "LIEF/asm/x86/opcodes.hpp"


/// x86/x86-64 architecture-related namespace
namespace LIEF::assembly::x86 {

/// This class represents a x86/x86-64 instruction
class LIEF_API Instruction : public assembly::Instruction {
  public:
  using assembly::Instruction::Instruction;

  using operands_it = iterator_range<Operand::Iterator>;

  /// The instruction opcode as defined in LLVM
  OPCODE opcode() const;

  /// Iterator over the operands of the current instruction
  operands_it operands() const LIEF_LIFETIMEBOUND;

  /// True if this instruction has a `LOCK` prefix
  bool has_lock_prefix() const;

  /// True if the `LOCK` prefix is architecturally valid on this instruction
  bool is_lockable() const;

  /// True if this instruction executes as an atomic read-modify-write
  bool is_atomic() const;

  /// Re-encoded copy of this instruction with a `LOCK` prefix added.
  ///
  /// If the instruction already has a `LOCK` prefix, it returns a plain copy.
  std::unique_ptr<Instruction> lock() const;

  /// Re-encoded copy of this instruction with the `LOCK` prefix removed.
  ///
  /// If the instruction does not have a `LOCK` prefix, it returns a plain copy
  /// or a nullptr if the `LOCK` semantic can't be removed.
  std::unique_ptr<Instruction> unlock() const;

  /// True if `inst` is an **effective** instance of x86::Instruction
  static bool classof(const assembly::Instruction* inst);

  ~Instruction() override = default;
};
}


#endif
