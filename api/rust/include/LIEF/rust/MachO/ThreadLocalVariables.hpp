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

#include "LIEF/MachO/ThreadLocalVariables.hpp"
#include "LIEF/rust/MachO/Section.hpp"
#include "LIEF/rust/Iterator.hpp"
#include "LIEF/rust/Mirror.hpp"

class MachO_ThreadLocalVariables_Thunk
  : public Mirror<LIEF::MachO::ThreadLocalVariables::Thunk> {
  public:
  using lief_t = LIEF::MachO::ThreadLocalVariables::Thunk;
  using Mirror::Mirror;

  auto func() const {
    return get().func;
  }
  auto key() const {
    return get().key;
  }
  auto offset() const {
    return get().offset;
  }
};

class MachO_ThreadLocalVariables : public MachO_Section {
  public:
  using lief_t = LIEF::MachO::ThreadLocalVariables;

  class it_thunks
    : public RandomRangeIterator<MachO_ThreadLocalVariables_Thunk,
                                 LIEF::MachO::ThreadLocalVariables::Iterator> {
    public:
    it_thunks(const MachO_ThreadLocalVariables::lief_t& src) :
      RandomRangeIterator(src.thunks()) {}
    auto next() {
      return RandomRangeIterator::next();
    }
    auto size() const {
      return RandomRangeIterator::size();
    }
  };

  MachO_ThreadLocalVariables(const lief_t& base) :
    MachO_Section(base) {}

  auto nb_thunks() const {
    return impl().nb_thunks();
  }

  auto thunks() const {
    return std::make_unique<it_thunks>(impl());
  }

  std::unique_ptr<MachO_ThreadLocalVariables_Thunk> get_thunk(uint64_t idx) const {
    return details::try_unique<MachO_ThreadLocalVariables_Thunk>(impl().get(idx));
  }

  void set_thunk(uint64_t idx, uint64_t func, uint64_t key, uint64_t offset) {
    impl().set(idx, lief_t::Thunk{func, key, offset});
  }

  static bool classof(const MachO_Section& sec) {
    return lief_t::classof(&as<LIEF::MachO::Section>(&sec));
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
  lief_t& impl() {
    return as<lief_t>(this);
  }
};
