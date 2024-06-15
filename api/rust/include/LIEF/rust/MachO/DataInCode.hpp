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
#include <memory>

#include "LIEF/MachO/DataInCode.hpp"
#include "LIEF/rust/MachO/LoadCommand.hpp"
#include "LIEF/rust/MachO/DataCodeEntry.hpp"
#include "LIEF/rust/Iterator.hpp"

class MachO_DataInCode : public MachO_Command {
  public:
  using lief_t = LIEF::MachO::DataInCode;
  class it_entries :
      public Iterator<MachO_DataCodeEntry, LIEF::MachO::DataInCode::it_const_entries>
  {
    public:
    it_entries(const MachO_DataInCode::lief_t& src)
      : Iterator(std::move(src.entries())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };
  MachO_DataInCode(const lief_t& base) : MachO_Command(base) {}
  uint32_t data_offset() const { return impl().data_offset(); };
  uint32_t data_size() const { return impl().data_size(); };
  auto content() const { return make_span(impl().content()); }

  auto entries() const {
    return std::make_unique<it_entries>(impl());
  }

  static bool classof(const MachO_Command& cmd) {
    return lief_t::classof(&cmd.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
