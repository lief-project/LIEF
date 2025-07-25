/* Copyright 2024 - 2025 R. Thomas
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
#include "LIEF/ELF/SymbolVersion.hpp"
#include "LIEF/rust/ELF/SymbolVersionAux.hpp"
#include "LIEF/rust/Mirror.hpp"

class ELF_SymbolVersion : private Mirror<LIEF::ELF::SymbolVersion> {
  public:
  using lief_t = LIEF::ELF::SymbolVersion;
  using Mirror::Mirror;

  auto value() const { return get().value();  }

  auto symbol_version_auxiliary() const {
    return details::try_unique<ELF_SymbolVersionAux>(get().symbol_version_auxiliary());
  }

  auto drop_version(uint16_t value) {
    get().drop_version(value);
  }

  auto as_local() { get().as_local(); }
  auto as_global() { get().as_global(); }
};
