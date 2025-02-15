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

#include "LIEF/PE/CodeIntegrity.hpp"
#include "LIEF/rust/Mirror.hpp"

class PE_CodeIntegrity : private Mirror<LIEF::PE::CodeIntegrity> {
  public:
  using lief_t = LIEF::PE::CodeIntegrity;
  using Mirror::Mirror;

  auto flags() const { return get().flags(); }
  auto catalog() const { return get().catalog(); }
  auto catalog_offset() const { return get().catalog_offset(); }
  auto reserved() const { return get().reserved(); }
};
