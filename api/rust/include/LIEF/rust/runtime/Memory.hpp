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

#include "LIEF/runtime/Memory.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/error.hpp"
#include "LIEF/rust/helpers.hpp"

class runtime_Memory_Chunk : public Mirror<LIEF::runtime::Memory::Chunk> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::runtime::Memory::Chunk;

  uint64_t addr() const {
    return get().addr();
  }
  uint64_t size() const {
    return get().size();
  }
  auto permissions() const {
    return get().permissions();
  }
  uint64_t page_start() const {
    return get().page_start();
  }
  uint64_t page_end() const {
    return get().page_end();
  }

  void change_permissions(uint32_t p) {
    get().change_permissions(p);
  }

  void make_x() {
    get().make_x();
  }
  void make_rw() {
    get().make_rw();
  }
  void make_rx() {
    get().make_rx();
  }
  void make_rwx() {
    get().make_rwx();
  }
  void make_ro() {
    get().make_ro();
  }

  void cache_flush() {
    get().cache_flush();
  }

  auto is_valid() const {
    return get().is_valid();
  }

  auto to_string() const {
    return to_unique_string(get().to_string());
  }
};

class runtime_Memory : public Mirror<LIEF::runtime::Memory> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::runtime::Memory;

  static auto mmap(uint64_t size, uint32_t flags, uint32_t permission) {
    return details::try_unique<runtime_Memory_Chunk>(lief_t::mmap(size, flags,
                                                                  permission));
  }

  static auto mmap_hint(uint64_t hint, uint64_t size, uint32_t flags,
                        uint32_t permission) {
    return details::try_unique<runtime_Memory_Chunk>(
        lief_t::mmap_hint(hint, size, flags, permission)
    );
  }

  static void munmap(runtime_Memory_Chunk& chunk, uint32_t& err) {
    details::make_error(lief_t::munmap(chunk.get()), err);
  }

  static void mprotect(runtime_Memory_Chunk& chunk, uint32_t flags,
                       uint32_t& err) {
    details::make_error(lief_t::mprotect(chunk.get(), flags), err);
  }
};
