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
#include "LIEF/MachO/SubFramework.hpp"
#include "LIEF/rust/MachO/LoadCommand.hpp"

class MachO_SubFramework : public MachO_Command {
  public:
  using lief_t = LIEF::MachO::SubFramework;
  MachO_SubFramework(const lief_t& base) : MachO_Command(base) {}
  std::string umbrella() const { return impl().umbrella(); }

  static bool classof(const MachO_Command& cmd) {
    return lief_t::classof(&cmd.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
