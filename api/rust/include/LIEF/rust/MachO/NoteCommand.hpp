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
#include "LIEF/rust/Span.hpp"
#include "LIEF/MachO/NoteCommand.hpp"
#include "LIEF/rust/MachO/LoadCommand.hpp"

class MachO_NoteCommand : public MachO_Command {
  public:
  using lief_t = LIEF::MachO::NoteCommand;
  MachO_NoteCommand(const lief_t& base) : MachO_Command(base) {}

  auto note_offset() const { return impl().note_offset(); }
  auto note_size() const { return impl().note_size(); }

  Span owner() const { return make_span(impl().owner()); }

  void set_note_offset(uint64_t value) {
    impl().note_offset(value);
  }

  void set_note_size(uint64_t value) {
    impl().note_size(value);
  }

  static bool classof(const MachO_Command& cmd) {
    return lief_t::classof(&cmd.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
  lief_t& impl() { return as<lief_t>(this); }
};
