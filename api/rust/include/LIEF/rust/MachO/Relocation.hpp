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
#include "LIEF/MachO/Relocation.hpp"
#include "LIEF/rust/MachO/Symbol.hpp"
#include "LIEF/rust/MachO/Section.hpp"
#include "LIEF/rust/MachO/SegmentCommand.hpp"
#include "LIEF/rust/Abstract/Relocation.hpp"

#include <memory>

class MachO_Relocation : public AbstractRelocation {
  public:
  using lief_t = LIEF::MachO::Relocation;
  MachO_Relocation(const lief_t& reloc) : AbstractRelocation(reloc) {}

  bool is_pc_relative() const { return impl().is_pc_relative(); };
  auto architecture() const { return to_int(impl().architecture()); };
  auto origin() const { return to_int(impl().origin()); };

  auto symbol() const {
    return details::try_unique<MachO_Symbol>(impl().symbol());
  }

  auto section() const {
    return details::try_unique<MachO_Section>(impl().section());
  }

  auto segment() const {
    return details::try_unique<MachO_SegmentCommand>(impl().segment());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
