/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include <numeric>
#include <iomanip>

#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/SubFramework.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

SubFramework::SubFramework() = default;
SubFramework& SubFramework::operator=(const SubFramework&) = default;
SubFramework::SubFramework(const SubFramework&) = default;
SubFramework::~SubFramework() = default;

SubFramework::SubFramework(const details::sub_framework_command& cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(cmd.cmd), cmd.cmdsize}
{}

SubFramework* SubFramework::clone() const {
  return new SubFramework(*this);
}

const std::string& SubFramework::umbrella() const {
  return umbrella_;
}

void SubFramework::umbrella(const std::string& u) {
  umbrella_ = u;
}

void SubFramework::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool SubFramework::operator==(const SubFramework& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool SubFramework::operator!=(const SubFramework& rhs) const {
  return !(*this == rhs);
}


bool SubFramework::classof(const LoadCommand* cmd) {
  // This must be sync with BinaryParser.tcc
  const LOAD_COMMAND_TYPES type = cmd->command();
  return type == LOAD_COMMAND_TYPES::LC_SUB_FRAMEWORK;
}

std::ostream& SubFramework::print(std::ostream& os) const {
  LoadCommand::print(os);
  os << std::left;
  os << std::endl;
  os << "Umbrella:" << umbrella();
  return os;
}


}
}
