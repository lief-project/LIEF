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
#include "LIEF/MachO/Section.hpp"
#include "LIEF/rust/Abstract/Section.hpp"
#include "LIEF/rust/Iterator.hpp"

class MachO_SegmentCommand;
class MachO_Relocation;

class MachO_Section : public AbstractSection {
  public:
  using lief_t = LIEF::MachO::Section;
  MachO_Section(const lief_t& sec) : AbstractSection(sec) {}

  class it_relocations :
      public Iterator<MachO_Relocation, LIEF::MachO::Section::it_const_relocations>
  {
    public:
    it_relocations(const MachO_Section::lief_t& src)
      : Iterator(std::move(src.relocations())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  std::string segment_name() const { return impl().segment_name(); }
  auto address() const { return impl().address(); }
  auto alignment() const { return impl().alignment(); }
  auto relocation_offset() const { return impl().relocation_offset(); }
  auto numberof_relocations() const { return impl().numberof_relocations(); }
  auto flags() const { return to_int(impl().flags()); }
  auto section_type() const { return to_int(impl().type()); }
  auto reserved1() const { return impl().reserved1(); }
  auto reserved2() const { return impl().reserved2(); }
  auto reserved3() const { return impl().reserved3(); }

  auto raw_flags() const { return impl().raw_flags(); }

  auto segment() const { return details::try_unique<MachO_SegmentCommand>(impl().segment()); }
  auto relocations() const { return std::make_unique<it_relocations>(impl()); }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
