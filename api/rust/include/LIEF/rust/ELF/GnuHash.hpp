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
#include "LIEF/ELF/GnuHash.hpp"
#include "LIEF/rust/Mirror.hpp"

class ELF_GnuHash : private Mirror<LIEF::ELF::GnuHash> {
  public:
  using lief_t = LIEF::ELF::GnuHash;
  using Mirror::Mirror;

  uint32_t nb_buckets() const { return get().nb_buckets(); }
  uint32_t symbol_index() const { return get().symbol_index(); }
  uint32_t shift2() const { return get().shift2(); }
  uint32_t maskwords() const { return get().maskwords(); }

  std::vector<uint64_t> bloom_filters() const { return get().bloom_filters(); }
  std::vector<uint32_t> buckets() const { return get().buckets(); }
  std::vector<uint32_t> hash_values() const { return get().hash_values(); }
};
