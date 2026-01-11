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

#include "LIEF/COFF/AuxiliarySymbols/AuxiliaryCLRToken.hpp"
#include "LIEF/rust/COFF/AuxiliarySymbol.hpp"
#include "LIEF/rust/COFF/Symbol.hpp"

class COFF_AuxiliaryCLRToken : public COFF_AuxiliarySymbol {
  public:
  using lief_t = LIEF::COFF::AuxiliaryCLRToken;
  COFF_AuxiliaryCLRToken(const lief_t& obj) : COFF_AuxiliarySymbol(obj) {}

  auto aux_type() const {
    return impl().aux_type();
  }

  auto reserved() const {
    return impl().reserved();
  }

  auto symbol_idx() const {
    return impl().symbol_idx();
  }

  auto symbol() const {
    return details::try_unique<COFF_Symbol>(impl().symbol());
  }

  auto rgb_reserved() const {
    return make_span(impl().rgb_reserved());
  }

  static bool classof(const COFF_AuxiliarySymbol& entry) {
    return lief_t::classof(&entry.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
