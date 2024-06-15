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
#include "LIEF/ELF/SymbolVersionRequirement.hpp"
#include "LIEF/rust/ELF/SymbolVersionAuxRequirement.hpp"
#include "LIEF/rust/Iterator.hpp"
#include <memory>

class ELF_SymbolVersionRequirement : private Mirror<LIEF::ELF::SymbolVersionRequirement> {
  public:
  using lief_t = LIEF::ELF::SymbolVersionRequirement;
  using Mirror::Mirror;

  uint16_t version() const { return get().version(); }
  uint32_t cnt() const { return get().cnt(); }
  std::string name() const { return get().name(); }

  class it_auxiliary_symbols :
      public Iterator<ELF_SymbolVersionAuxRequirement, LIEF::ELF::SymbolVersionRequirement::it_const_aux_requirement>
  {
    public:
    it_auxiliary_symbols(const ELF_SymbolVersionRequirement::lief_t& src)
      : Iterator(std::move(src.auxiliary_symbols())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  auto auxiliary_symbols() const {
    return std::make_unique<it_auxiliary_symbols>(get());
  }
};
