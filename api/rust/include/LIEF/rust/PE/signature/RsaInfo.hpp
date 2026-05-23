/* Copyright 2024 - 2026 R. Thomas
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

#include "LIEF/PE/signature/RsaInfo.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"

class PE_RsaInfo : private Mirror<LIEF::PE::RsaInfo> {
  public:
  using lief_t = LIEF::PE::RsaInfo;
  using Mirror::Mirror;

  uint32_t key_size() const {
    return get().key_size();
  }
  auto has_public_key() const {
    return get().has_public_key();
  }
  auto has_private_key() const {
    return get().has_private_key();
  }
  auto N() const {
    return make_unique_vector<uint8_t>(get().N());
  }
  auto E() const {
    return make_unique_vector<uint8_t>(get().E());
  }
  auto D() const {
    return make_unique_vector<uint8_t>(get().D());
  }
  auto P() const {
    return make_unique_vector<uint8_t>(get().P());
  }
  auto Q() const {
    return make_unique_vector<uint8_t>(get().Q());
  }
};
