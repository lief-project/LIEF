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
#include "LIEF/ELF/SymbolVersionAuxRequirement.hpp"
#include "LIEF/rust/ELF/SymbolVersionAux.hpp"

class ELF_SymbolVersionAuxRequirement : public ELF_SymbolVersionAux {
  public:
  using lief_t = LIEF::ELF::SymbolVersionAuxRequirement;
  ELF_SymbolVersionAuxRequirement(const lief_t& sym) : ELF_SymbolVersionAux(sym) {}

  uint32_t hash() const { return impl().hash(); }
  uint16_t flags() const { return impl().flags(); }
  uint16_t other() const { return impl().other(); }

  auto name() const { return ELF_SymbolVersionAux::name(); }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
