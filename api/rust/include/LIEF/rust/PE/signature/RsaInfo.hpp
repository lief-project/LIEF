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

#include "LIEF/PE/signature/RsaInfo.hpp"
#include "LIEF/rust/Mirror.hpp"

class PE_RsaInfo : private Mirror<LIEF::PE::RsaInfo> {
  public:
  using lief_t = LIEF::PE::RsaInfo;
  using Mirror::Mirror;

  uint32_t key_size() const { return get().key_size(); }
  bool has_public_key() const { return get().has_public_key(); }
  bool has_private_key() const { return get().has_private_key(); }
  std::vector<uint8_t> N() const { return get().N(); }
  std::vector<uint8_t> E() const { return get().E(); }
  std::vector<uint8_t> D() const { return get().D(); }
  std::vector<uint8_t> P() const { return get().P(); }
  std::vector<uint8_t> Q() const { return get().Q(); }
};
