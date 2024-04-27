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
#include "LIEF/ELF/SymbolVersionDefinition.hpp"
#include "LIEF/rust/Mirror.hpp"

class ELF_SymbolVersionDefinition : private Mirror<LIEF::ELF::SymbolVersionDefinition> {
  public:
  using lief_t = LIEF::ELF::SymbolVersionDefinition;
  using Mirror::Mirror;

  uint16_t version() const { return get().version(); }
  uint16_t flags() const { return get().flags(); }
  uint16_t ndx() const { return get().ndx(); }
  uint32_t hash() const { return get().hash(); }
};
