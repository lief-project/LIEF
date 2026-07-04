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
#include <LIEF/asm/mips/operands/Memory.hpp>

#include "LIEF/rust/asm/mips/Operand.hpp"
#include "LIEF/rust/helpers.hpp"

class asm_mips_operands_Memory_offset_t {
  public:
  uint64_t value = 0;
  uint32_t enum_type = 0;
};

class asm_mips_operands_Memory : public asm_mips_Operand {
  public:
  using lief_t = LIEF::assembly::mips::operands::Memory;

  uint64_t base() const {
    return to_int(impl().base());
  }

  asm_mips_operands_Memory_offset_t offset() const {
    const lief_t::offset_t off = impl().offset();
    uint64_t value = off.type == lief_t::offset_t::TYPE::REG ?
                         (uint64_t)to_int(off.reg) :
                         (uint64_t)off.displacement;
    return {
        /*.value = */ value,
        /*.enum_type = */ (uint32_t)to_int(off.type),
    };
  }

  static auto classof(const asm_mips_Operand& inst) {
    return lief_t::classof(&inst.get());
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
};
