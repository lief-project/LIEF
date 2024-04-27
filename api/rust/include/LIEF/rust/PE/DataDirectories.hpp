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
#include "LIEF/PE/DataDirectory.hpp"
#include "LIEF/rust/PE/Section.hpp"
#include "LIEF/rust/Mirror.hpp"

class PE_DataDirectory : private Mirror<LIEF::PE::DataDirectory> {
  public:
  using lief_t = LIEF::PE::DataDirectory;
  using Mirror::Mirror;

  uint32_t RVA() const { return get().RVA(); }
  uint32_t size() const { return get().size(); }
  uint32_t get_type() const { return to_int(get().type()); }

  auto section() const {
    return details::try_unique<PE_Section>(get().section());
  }

};
