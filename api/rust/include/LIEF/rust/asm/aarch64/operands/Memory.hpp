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
#include <LIEF/asm/aarch64/operands/Memory.hpp>

#include "LIEF/rust/asm/aarch64/Operand.hpp"
#include "LIEF/rust/helpers.hpp"

class asm_aarch64_operands_Memory_offset_t {
  public:
  uint64_t value;
  uint32_t enum_type;
};

class asm_aarch64_operands_Memory_shift_info_t {
  public:
  int32_t enum_type;
  int8_t value;
};

class asm_aarch64_operands_Memory : public asm_aarch64_Operand {
  public:
  using lief_t = LIEF::assembly::aarch64::operands::Memory;

  uint64_t base() const { return to_int(impl().base()); }

  asm_aarch64_operands_Memory_offset_t offset() const {
    const lief_t::offset_t off = impl().offset();
    return {
      /*.value = */(uint64_t)off.reg,
      /*.type = */(uint32_t)to_int(off.type),
    };
  }

  asm_aarch64_operands_Memory_shift_info_t shift() const {
    const lief_t::shift_info_t info = impl().shift();
    return {
      /*.type = */(int32_t)info.type,
      /*.value = */info.value,
    };
  }

  static bool classof(const asm_aarch64_Operand& inst) {
    return lief_t::classof(&inst.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
