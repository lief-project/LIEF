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

#include "LIEF/PE/Header.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"

class PE_Header : private Mirror<LIEF::PE::Header> {
  public:
  using lief_t = LIEF::PE::Header;
  using Mirror::Mirror;

  auto signature() const {
    return details::make_vector(get().signature());
  }

  uint32_t machine() const { return to_int(get().machine()); }
  uint16_t numberof_sections() const { return get().numberof_sections(); }
  uint32_t time_date_stamp() const { return get().time_date_stamp(); }
  uint32_t pointerto_symbol_table() const { return get().pointerto_symbol_table(); }
  uint32_t numberof_symbols() const { return get().numberof_symbols(); }
  uint16_t sizeof_optional_header() const { return get().sizeof_optional_header(); }
  uint32_t characteristics() const { return get().characteristics(); }
};
