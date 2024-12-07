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
#include "LIEF/rust/helpers.hpp"
#include "LIEF/rust/error.hpp"

#include "LIEF/rust/Mirror.hpp"

class asm_Instruction : public Mirror<LIEF::assembly::Instruction> {
  public:
  using lief_t = LIEF::assembly::Instruction;
  using Mirror::Mirror;

  auto address() const { return get().address(); }

  uint64_t size() const { return get().size(); }

  auto raw() const { return  make_span(get().raw()); }

  auto mnemonic() const { return get().mnemonic(); }

  auto to_string() const { return get().to_string(/*with_address=*/true); }
  auto to_string_no_address() const { return get().to_string(/*with_address=*/false); }

  auto is_call() const { return get().is_call(); }

  auto is_terminator() const { return get().is_terminator(); }

  auto is_branch() const { return get().is_branch(); }

  auto is_syscall() const { return get().is_syscall(); }
  auto is_memory_access() const { return get().is_memory_access(); }
  auto is_move_reg() const { return get().is_move_reg(); }
  auto is_add() const { return get().is_add(); }
  auto is_trap() const { return get().is_trap(); }
  auto is_barrier() const { return get().is_barrier(); }
  auto is_return() const { return get().is_return(); }
  auto is_indirect_branch() const { return get().is_indirect_branch(); }
  auto is_conditional_branch() const { return get().is_conditional_branch(); }
  auto is_unconditional_branch() const { return get().is_unconditional_branch(); }
  auto is_compare() const { return get().is_compare(); }
  auto is_move_immediate() const { return get().is_move_immediate(); }
  auto is_bitcast() const { return get().is_bitcast(); }
  uint64_t memory_access() const { return to_int(get().memory_access()); }
  uint64_t branch_target(uint32_t& err) const {
    return details::make_error(get().branch_target(), err);
  }
};
