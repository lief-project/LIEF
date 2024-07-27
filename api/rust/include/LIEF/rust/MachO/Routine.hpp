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
#include "LIEF/MachO/Routine.hpp"
#include "LIEF/rust/MachO/LoadCommand.hpp"

class MachO_Routine : public MachO_Command {
  public:
  using lief_t = LIEF::MachO::Routine;
  MachO_Routine(const lief_t& base) : MachO_Command(base) {}

  static bool classof(const MachO_Command& cmd) {
    return lief_t::classof(&cmd.get());
  }

  auto init_address() const { return impl().init_address(); }
  auto init_module() const { return impl().init_module(); }

  auto reserved1() const { return impl().reserved1(); }
  auto reserved2() const { return impl().reserved2(); }
  auto reserved3() const { return impl().reserved3(); }
  auto reserved4() const { return impl().reserved4(); }
  auto reserved5() const { return impl().reserved5(); }
  auto reserved6() const { return impl().reserved6(); }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
