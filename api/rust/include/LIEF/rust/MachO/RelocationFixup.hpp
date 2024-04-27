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
#include "LIEF/MachO/RelocationFixup.hpp"
#include "LIEF/rust/MachO/Relocation.hpp"

class MachO_RelocationFixup : public MachO_Relocation {
  public:
  using lief_t = LIEF::MachO::RelocationFixup;
  MachO_RelocationFixup(const lief_t& base) : MachO_Relocation(base) {}

  uint64_t target() const { return impl().target(); }
  uint32_t ptr_format() const { return impl().ptr_format(); }
  uint32_t offset() const { return impl().offset(); }

  static bool classof(const MachO_Relocation& reloc) {
    return lief_t::classof(*static_cast<const MachO_Relocation::lief_t*>(&reloc.get()));
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
