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

#include "LIEF/PE/debug/PogoEntry.hpp"
#include "LIEF/rust/Mirror.hpp"

class PE_PogoEntry : private Mirror<LIEF::PE::PogoEntry> {
  public:
  using lief_t = LIEF::PE::PogoEntry;
  using Mirror::Mirror;

  uint32_t start_rva() const { return get().start_rva(); }
  uint32_t size() const { return get().size(); }
  std::string name() const { return get().name(); }
};
