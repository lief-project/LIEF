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

#include "LIEF/MachO/FunctionVariants.hpp"
#include "LIEF/rust/MachO/LoadCommand.hpp"

#include "LIEF/rust/Iterator.hpp"

class MachO_FunctionVariants_RuntimeTableEntry :
  public Mirror<LIEF::MachO::FunctionVariants::RuntimeTableEntry>
{
  public:
  using lief_t = LIEF::MachO::FunctionVariants::RuntimeTableEntry;
  using Mirror::Mirror;

  auto implementation() const { return get().impl(); }
  auto another_table() const { return get().another_table(); }
  auto flag_bit_nums() const { return make_span(get().flag_bit_nums()); }
  auto flags() const {
    std::vector<uint32_t> out;
    const std::vector<lief_t::FLAGS> flags = get().flags();
    std::transform(flags.begin(), flags.end(), std::back_inserter(out),
      [] (lief_t::FLAGS f) { return (uint32_t)f; }
    );
    return out;
  }

  auto to_string() const { return get().to_string(); }
};

class MachO_FunctionVariants_RuntimeTable :
  public Mirror<LIEF::MachO::FunctionVariants::RuntimeTable>
{
  public:
  using lief_t = LIEF::MachO::FunctionVariants::RuntimeTable;
  using Mirror::Mirror;

  class it_entries :
      public Iterator<MachO_FunctionVariants_RuntimeTableEntry, lief_t::it_const_entries>
  {
    public:
    it_entries(const MachO_FunctionVariants_RuntimeTable::lief_t& src)
      : Iterator(std::move(src.entries())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  auto kind() const { return to_int(get().kind()); }
  auto offset() const { return get().offset(); }
  auto entries() const { return std::make_unique<it_entries>(get()); }

  auto to_string() const { return get().to_string(); }
};

class MachO_FunctionVariants : public MachO_Command {
  public:
  using lief_t = LIEF::MachO::FunctionVariants;

  class it_runtime_table :
      public Iterator<MachO_FunctionVariants_RuntimeTable, lief_t::it_const_runtime_table>
  {
    public:
    it_runtime_table(const MachO_FunctionVariants::lief_t& src)
      : Iterator(std::move(src.runtime_table())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  MachO_FunctionVariants(const lief_t& base) : MachO_Command(base) {}

  auto data_offset() const { return impl().data_offset(); }
  auto data_size() const { return impl().data_size(); }

  auto content() const { return make_span(impl().content()); }

  auto runtime_table() const { return std::make_unique<it_runtime_table>(impl()); }

  static bool classof(const MachO_Command& cmd) {
    return lief_t::classof(&cmd.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
