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
#include "LIEF/MachO/ThreadCommand.hpp"
#include "LIEF/rust/MachO/LoadCommand.hpp"

class MachO_ThreadCommand : public MachO_Command {
  public:
  using lief_t = LIEF::MachO::ThreadCommand;
  MachO_ThreadCommand(const lief_t& base) : MachO_Command(base) {}
  auto flavor() const { return impl().flavor(); }
  auto count() const { return impl().count(); }
  int32_t architecture() const { return to_int(impl().architecture()); }
  auto pc() const { return impl().pc(); }

  auto state() const { return make_span(impl().state()); }

  static bool classof(const MachO_Command& cmd) {
    return lief_t::classof(&cmd.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
