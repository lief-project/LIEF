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
#include <LIEF/asm/aarch64/operands/Register.hpp>

#include "LIEF/rust/asm/aarch64/Operand.hpp"
#include "LIEF/rust/helpers.hpp"

class asm_aarch64_operands_Register_reg_t {
  public:
  uint64_t reg;
  uint32_t enum_type;
};

class asm_aarch64_operands_Register : public asm_aarch64_Operand {
  public:
  using lief_t = LIEF::assembly::aarch64::operands::Register;

  asm_aarch64_operands_Register_reg_t value() const {
    lief_t::reg_t info = impl().value();
    return {
      /*.reg =*/(uint64_t)to_int(info.reg),
      /*.enum_type =*/(uint32_t)to_int(info.type),
    };
  }

  static bool classof(const asm_aarch64_Operand& inst) {
    return lief_t::classof(&inst.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
