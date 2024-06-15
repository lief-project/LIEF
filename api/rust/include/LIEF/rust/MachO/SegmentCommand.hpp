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
#include "LIEF/MachO/SegmentCommand.hpp"
#include "LIEF/rust/MachO/LoadCommand.hpp"
#include "LIEF/rust/MachO/Section.hpp"
#include "LIEF/rust/MachO/Relocation.hpp"

class MachO_SegmentCommand : public MachO_Command {
  using lief_t = LIEF::MachO::SegmentCommand;
  public:
  class it_relocations :
      public Iterator<MachO_Relocation, LIEF::MachO::SegmentCommand::it_const_relocations>
  {
    public:
    it_relocations(const MachO_SegmentCommand::lief_t& src)
      : Iterator(std::move(src.relocations())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_sections :
      public Iterator<MachO_Section, LIEF::MachO::SegmentCommand::it_const_sections>
  {
    public:
    it_sections(const MachO_SegmentCommand::lief_t& src)
      : Iterator(std::move(src.sections())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  MachO_SegmentCommand(const lief_t& base) : MachO_Command(base) {}

  std::string name() const { return impl().name(); };
  uint64_t virtual_address() const { return impl().virtual_address(); };
  uint64_t virtual_size() const { return impl().virtual_size(); };
  uint64_t file_size() const { return impl().file_size(); };
  uint64_t file_offset() const { return impl().file_offset(); };
  uint32_t max_protection() const { return impl().max_protection(); };
  uint32_t init_protection() const { return impl().init_protection(); };
  uint32_t numberof_sections() const { return impl().numberof_sections(); };
  uint32_t flags() const { return impl().flags(); };
  auto content() const { return make_span(impl().content()); }

  auto sections() const { return std::make_unique<it_sections>(impl()); }
  auto relocations() const { return std::make_unique<it_relocations>(impl()); }

  static bool classof(const MachO_Command& cmd) {
    return lief_t::classof(&cmd.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
