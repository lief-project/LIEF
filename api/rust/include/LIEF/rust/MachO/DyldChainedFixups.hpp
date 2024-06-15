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
#include "LIEF/MachO/DyldChainedFixups.hpp"
#include "LIEF/rust/MachO/LoadCommand.hpp"
#include "LIEF/rust/MachO/ChainedBindingInfo.hpp"

class MachO_DyldChainedFixups : public MachO_Command {
  public:
  using lief_t = LIEF::MachO::DyldChainedFixups;
  class it_bindings :
      public Iterator<MachO_ChainedBindingInfo, LIEF::MachO::DyldChainedFixups::it_const_binding_info>
  {
    public:
    it_bindings(const MachO_DyldChainedFixups::lief_t& src)
      : Iterator(std::move(src.bindings())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };
  MachO_DyldChainedFixups(const lief_t& base) : MachO_Command(base) {}

  uint32_t data_offset() const { return impl().data_offset(); }
  uint32_t data_size() const { return impl().data_size(); }
  uint32_t fixups_version() const { return impl().fixups_version(); }
  uint32_t starts_offset() const { return impl().starts_offset(); }
  uint32_t imports_offset() const { return impl().imports_offset(); }
  uint32_t symbols_offset() const { return impl().symbols_offset(); }
  uint32_t imports_count() const { return impl().imports_count(); }
  uint32_t symbols_format() const { return impl().symbols_format(); }
  auto imports_format() const { return to_int(impl().imports_format()); }

  auto bindings() const { return std::make_unique<it_bindings>(impl()); }

  static bool classof(const MachO_Command& cmd) {
    return lief_t::classof(&cmd.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
