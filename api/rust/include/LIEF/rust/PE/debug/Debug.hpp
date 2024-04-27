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

#include "LIEF/PE/debug/Debug.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"

class PE_Debug : public Mirror<LIEF::PE::Debug> {
  public:
  using lief_t = LIEF::PE::Debug;
  using Mirror::Mirror;

  uint32_t characteristics() const { return get().characteristics(); }
  uint32_t timestamp() const { return get().timestamp(); }
  uint16_t major_version() const { return get().major_version(); }
  uint16_t minor_version() const { return get().minor_version(); }
  uint32_t get_type() const { return to_int(get().type()); }
  uint32_t sizeof_data() const { return get().sizeof_data(); }
  uint32_t addressof_rawdata() const { return get().addressof_rawdata(); }
  uint32_t pointerto_rawdata() const { return get().pointerto_rawdata(); }
};
