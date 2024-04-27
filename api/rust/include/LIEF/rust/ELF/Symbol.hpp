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
#include "LIEF/ELF/Symbol.hpp"
#include "LIEF/rust/ELF/Section.hpp"
#include "LIEF/rust/ELF/SymbolVersion.hpp"
#include "LIEF/rust/Abstract/Symbol.hpp"
#include "LIEF/rust/helpers.hpp"

class ELF_Symbol : public AbstractSymbol {
  public:
  using lief_t = LIEF::ELF::Symbol;
  ELF_Symbol(const lief_t& obj) : AbstractSymbol(obj) {}
  uint32_t get_type() const { return to_int(impl().type()); }

  uint32_t binding() const { return to_int(impl().binding()); }
  uint8_t information() const { return impl().information(); }
  uint8_t other() const { return impl().other(); }
  uint16_t section_idx() const { return impl().section_idx(); }
  uint32_t visibility() const { return to_int(impl().visibility()); }

  auto section() const { return details::try_unique<ELF_Section>(impl().section());}
  auto symbol_version() const { return details::try_unique<ELF_SymbolVersion>(impl().symbol_version());}

  std::string to_string() const { return details::to_string(impl()); }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
