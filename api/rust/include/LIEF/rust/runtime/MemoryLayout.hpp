/* Copyright 2022 - 2026 R. Thomas
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

#include "LIEF/runtime/MemoryLayout.hpp"
#include "LIEF/rust/Iterator.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"

class runtime_MemoryLayout_Region
  : public Mirror<LIEF::runtime::MemoryLayout::Region> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::runtime::MemoryLayout::Region;

  auto name() const {
    return to_unique_string(get().name());
  }

  uint64_t addr() const {
    return get().addr();
  }

  uint64_t size() const {
    return get().size();
  }

  uint64_t end_addr() const {
    return get().end_addr();
  }

  auto contains(uint64_t addr) const {
    return get().contains(addr);
  }

  auto to_string() const {
    return to_unique_string(get().to_string());
  }
};

class runtime_it_memory_layout
  : public ForwardIterator<runtime_MemoryLayout_Region,
                           LIEF::runtime::MemoryLayout::Iterator> {
  public:
  runtime_it_memory_layout() :
    ForwardIterator(LIEF::runtime::memory_layout()) {}

  auto next() {
    return ForwardIterator::next();
  }
};

inline auto runtime_memory_layout() {
  return std::make_unique<runtime_it_memory_layout>();
}
