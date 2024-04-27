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
#include "LIEF/ELF/Relocation.hpp"
#include "LIEF/rust/Abstract/Relocation.hpp"
#include "LIEF/rust/ELF/Symbol.hpp"
#include "LIEF/rust/ELF/Section.hpp"

class ELF_Relocation : public AbstractRelocation {
  public:
  using lief_t = LIEF::ELF::Relocation;
  ELF_Relocation(const lief_t& reloc) : AbstractRelocation(reloc) {}

  int64_t addend() const { return impl().addend(); }
  uint32_t get_type() const { return to_int(impl().type()); }
  bool is_rela() const { return impl().is_rela(); }
  bool is_rel() const { return impl().is_rel(); }

  uint32_t info() const { return impl().info(); }
  uint32_t architecture() const { return to_int(impl().architecture()); }
  uint32_t purpose() const { return to_int(impl().purpose()); }
  uint32_t encoding() const { return to_int(impl().encoding()); }

  auto symbol() const {
    return details::try_unique<ELF_Symbol>(impl().symbol());
  }

  auto section() const {
    return details::try_unique<ELF_Section>(impl().section());
  }

  auto symbol_table() const {
    return details::try_unique<ELF_Section>(impl().symbol_table());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
