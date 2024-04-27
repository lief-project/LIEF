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
#include <cstdint>

#include "LIEF/PE/RelocationEntry.hpp"
#include "LIEF/rust/Abstract/Relocation.hpp"
#include "LIEF/rust/helpers.hpp"

class PE_RelocationEntry : public AbstractRelocation {
  public:
  using lief_t = LIEF::PE::RelocationEntry;
  PE_RelocationEntry(const lief_t& obj) : AbstractRelocation(obj) {}

  uint64_t position() const { return impl().position(); }
  uint32_t get_type() const { return to_int(impl().type()); }
  uint16_t data() const { return impl().data(); }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
