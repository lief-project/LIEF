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

#include "LIEF/PE/debug/Debug.hpp"
#include "LIEF/rust/PE/Section.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"
#include "LIEF/rust/Span.hpp"

class PE_Debug : public Mirror<LIEF::PE::Debug> {
  public:
  using lief_t = LIEF::PE::Debug;
  using Mirror::Mirror;

  auto characteristics() const { return get().characteristics(); }
  auto timestamp() const { return get().timestamp(); }
  auto major_version() const { return get().major_version(); }
  auto minor_version() const { return get().minor_version(); }
  uint32_t get_type() const { return to_int(get().type()); }
  auto sizeof_data() const { return get().sizeof_data(); }
  auto addressof_rawdata() const { return get().addressof_rawdata(); }
  auto pointerto_rawdata() const { return get().pointerto_rawdata(); }

  auto section() const {
    return details::try_unique<PE_Section>(get().section());
  }

  Span payload() const { return make_span(get().payload()); }

  void set_characteristics(uint32_t value) { get().characteristics(value); }
  void set_timestamp(uint32_t value) { get().timestamp(value); }
  void set_major_version(uint16_t value) { get().major_version(value); }
  void set_minor_version(uint16_t value) { get().minor_version(value); }
};
