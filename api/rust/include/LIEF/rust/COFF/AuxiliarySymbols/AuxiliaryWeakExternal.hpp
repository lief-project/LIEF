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

#include "LIEF/COFF/AuxiliarySymbols/AuxiliaryWeakExternal.hpp"
#include "LIEF/rust/COFF/AuxiliarySymbol.hpp"
#include "LIEF/rust/helpers.hpp"
#include "LIEF/rust/Span.hpp"

class COFF_AuxiliaryWeakExternal : public COFF_AuxiliarySymbol {
  public:
  using lief_t = LIEF::COFF::AuxiliaryWeakExternal;
  COFF_AuxiliaryWeakExternal(const lief_t& obj) : COFF_AuxiliarySymbol(obj) {}

  auto sym_idx() const { return impl().sym_idx(); }
  auto characteristics() const { return to_int(impl().characteristics()); }

  auto padding() const {
    return make_span(impl().padding());
  }

  static bool classof(const COFF_AuxiliarySymbol& entry) {
    return lief_t::classof(&entry.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
