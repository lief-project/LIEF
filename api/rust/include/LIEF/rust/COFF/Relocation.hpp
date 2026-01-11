
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
#include <cstdint>

#include "LIEF/COFF/Relocation.hpp"
#include "LIEF/rust/COFF/Symbol.hpp"
#include "LIEF/rust/Abstract/Relocation.hpp"

class COFF_Section;

class COFF_Relocation : public AbstractRelocation {
  public:
  using lief_t = LIEF::COFF::Relocation;
  COFF_Relocation(const lief_t& obj) : AbstractRelocation(obj) {}

  auto symbol_idx() const {
    return impl().symbol_idx();
  }

  auto symbol() const {
    return details::try_unique<COFF_Symbol>(impl().symbol());
  }

  auto get_type() const {
    return to_int(impl().type());
  }

  auto section() const {
    return details::try_unique<COFF_Section>(impl().section());
  }

  auto to_string() const {
    return impl().to_string();
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
