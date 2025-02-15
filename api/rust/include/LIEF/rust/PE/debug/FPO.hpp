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
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/Iterator.hpp"
#include "LIEF/rust/PE/debug/Debug.hpp"
#include "LIEF/PE/debug/FPO.hpp"


class PE_FPO_entry_t : private Mirror<LIEF::PE::FPO::entry_t> {
  public:
  using lief_t = LIEF::PE::FPO::entry_t;
  using Mirror::Mirror;

  auto rva() const { return get().rva; }
  auto proc_size() const { return get().proc_size; }
  auto nb_locals() const { return get().nb_locals; }
  auto parameters_size() const { return get().parameters_size; }
  auto prolog_size() const { return get().prolog_size; }
  auto nb_saved_regs() const { return get().nb_saved_regs; }
  auto use_seh() const { return get().use_seh; }
  auto use_bp() const { return get().use_bp; }
  auto reserved() const { return get().reserved; }
  auto get_type() const { return to_int(get().type); }
  auto to_string() const { return get().to_string(); }
};

class PE_FPO : public PE_Debug {
  public:
  using lief_t = LIEF::PE::FPO;
  PE_FPO(const lief_t& obj) : PE_Debug(obj) {}

  class it_entries :
      public Iterator<PE_FPO_entry_t, LIEF::PE::FPO::it_const_entries>
  {
    public:
    it_entries(const PE_FPO::lief_t& src)
      : Iterator(std::move(src.entries())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  auto entries() const {
    return std::make_unique<it_entries>(impl());
  }

  static bool classof(const PE_Debug& entry) {
    return lief_t::classof(&entry.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
