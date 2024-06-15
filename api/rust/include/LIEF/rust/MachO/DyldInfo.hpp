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
#include <LIEF/MachO/DyldInfo.hpp>

#include "LIEF/rust/MachO/LoadCommand.hpp"
#include "LIEF/rust/MachO/BindingInfo.hpp"
#include "LIEF/rust/MachO/DyldBindingInfo.hpp"
#include "LIEF/rust/MachO/ExportInfo.hpp"

#include <memory>

class MachO_DyldInfo : public MachO_Command {
  public:
  using lief_t = LIEF::MachO::DyldInfo;
  class it_bindings :
      public Iterator<MachO_DyldBindingInfo, LIEF::MachO::DyldInfo::it_const_binding_info>
  {
    public:
    it_bindings(const MachO_DyldInfo::lief_t& src)
      : Iterator(std::move(src.bindings())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_exports :
      public Iterator<MachO_ExportInfo, LIEF::MachO::DyldInfo::it_const_export_info>
  {
    public:
    it_exports(const MachO_DyldInfo::lief_t& src)
      : Iterator(std::move(src.exports())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  MachO_DyldInfo(const lief_t& base) : MachO_Command(base) {}

  auto bindings() const { return std::make_unique<it_bindings>(impl()); }
  auto exports() const { return std::make_unique<it_exports>(impl()); }

  auto rebase_opcodes() const { return make_span(impl().rebase_opcodes()); }
  auto bind_opcodes() const { return make_span(impl().bind_opcodes()); }
  auto weak_bind_opcodes() const { return make_span(impl().weak_bind_opcodes()); }
  auto lazy_bind_opcodes() const { return make_span(impl().lazy_bind_opcodes()); }
  auto export_trie() const { return make_span(impl().export_trie()); }

  static bool classof(const MachO_Command& cmd) {
    return lief_t::classof(&cmd.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
