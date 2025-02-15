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

  auto machine() const { return to_int(get().machine()); }
  auto numberof_sections() const { return get().numberof_sections(); }
  auto time_date_stamp() const { return get().time_date_stamp(); }
  auto pointerto_symbol_table() const { return get().pointerto_symbol_table(); }
  auto numberof_symbols() const { return get().numberof_symbols(); }
  auto sizeof_optional_header() const { return get().sizeof_optional_header(); }
  auto characteristics() const { return get().characteristics(); }

  void set_machine(uint32_t value) {
    get().machine((lief_t::MACHINE_TYPES)value);
  }

  void set_numberof_sections(uint16_t value) {
    get().numberof_sections(value);
  }

  void set_time_date_stamp(uint32_t value) {
    get().time_date_stamp(value);
  }

  void set_pointerto_symbol_table(uint32_t value) {
    get().pointerto_symbol_table(value);
  }

  void set_numberof_symbols(uint32_t value) {
    get().numberof_symbols(value);
  }

  void set_sizeof_optional_header(uint16_t value) {
    get().sizeof_optional_header(value);
  }

  void set_characteristics(uint32_t value) {
    get().characteristics(value);
  }

  void add_characteristic(uint32_t value) {
    get().add_characteristic((lief_t::CHARACTERISTICS)value);
  }

  void remove_characteristic(uint32_t value) {
    get().remove_characteristic((lief_t::CHARACTERISTICS)value);
  }

};
