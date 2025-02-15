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

#include "LIEF/PE/TLS.hpp"
#include "LIEF/rust/PE/Section.hpp"
#include "LIEF/rust/PE/DataDirectories.hpp"
#include "LIEF/rust/Mirror.hpp"

class PE_TLS : public Mirror<LIEF::PE::TLS> {
  public:
  using lief_t = LIEF::PE::TLS;
  using Mirror::Mirror;

  static auto create() {
    return std::make_unique<PE_TLS>(std::make_unique<lief_t>());
  }

  std::vector<uint64_t> callbacks() const { return get().callbacks(); }

  auto addressof_index() const { return get().addressof_index(); }
  auto addressof_callbacks() const { return get().addressof_callbacks(); }
  auto sizeof_zero_fill() const { return get().sizeof_zero_fill(); }
  auto characteristics() const { return get().characteristics(); }

  auto data_template() const { return make_span(get().data_template()); }
  auto addressof_raw_data() const {
    return details::make_vector(get().addressof_raw_data());
  }

  auto section() const {
    return details::try_unique<PE_Section>(get().section()); // NOLINT(lang-analyzer-cplusplus.NewDeleteLeaks)
  }
  auto data_directory() const {
    return details::try_unique<PE_DataDirectory>(get().directory()); // NOLINT(lang-analyzer-cplusplus.NewDeleteLeaks)
  }

  void add_callback(uint64_t addr) {
    get().add_callback(addr);
  }

  void set_callbacks(const uint64_t* ptr, size_t size) {
    get().callbacks({ptr, ptr + size});
  }

  void set_addressof_index(uint64_t value) {
    get().addressof_index(value);
  }

  void set_addressof_callback(uint64_t value) {
    get().addressof_callbacks(value);
  }

  void set_sizeof_zero_fill(uint32_t value) {
    get().sizeof_zero_fill(value);
  }

  void set_characteristics(uint32_t value) {
    get().characteristics(value);
  }

  void set_data_template(const uint8_t* ptr, size_t size) {
    get().data_template({ptr, ptr + size});
  }
};
