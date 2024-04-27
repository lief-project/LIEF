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

#include "LIEF/PE/ImportEntry.hpp"
#include "LIEF/rust/Abstract/Symbol.hpp"

class PE_ImportEntry : public AbstractSymbol {
  public:
  using lief_t = LIEF::PE::ImportEntry;
  PE_ImportEntry(const lief_t& info) : AbstractSymbol(info) {}

  bool is_ordinal() const { return impl().is_ordinal(); }
  uint16_t ordinal() const { return impl().ordinal(); }
  uint64_t hint_name_rva() const { return impl().hint_name_rva(); }
  uint16_t hint() const { return impl().hint(); }
  uint64_t iat_value() const { return impl().iat_value(); }
  uint64_t data() const { return impl().data(); }
  uint64_t iat_address() const { return impl().iat_address(); }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
