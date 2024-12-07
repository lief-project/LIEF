/* Copyright 2024 R. Thomas
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
#include <LIEF/asm/x86/operands/Memory.hpp>

#include "LIEF/rust/asm/x86/Operand.hpp"
#include "LIEF/rust/helpers.hpp"

class asm_x86_operands_Memory : public asm_x86_Operand {
  public:
  using lief_t = LIEF::assembly::x86::operands::Memory;

  uint64_t base() const { return to_int(impl().base()); }
  uint64_t scaled_register() const { return to_int(impl().scaled_register()); }
  uint64_t segment_register() const { return to_int(impl().segment_register()); }

  auto scale() const { return impl().scale(); }
  auto displacement() const { return impl().displacement(); }

  static bool classof(const asm_x86_Operand& inst) {
    return lief_t::classof(&inst.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
