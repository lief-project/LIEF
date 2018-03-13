/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#include <iomanip>

#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/DylinkerCommand.hpp"

namespace LIEF {
namespace MachO {

DylinkerCommand::DylinkerCommand(void) = default;
DylinkerCommand& DylinkerCommand::operator=(const DylinkerCommand&) = default;
DylinkerCommand::DylinkerCommand(const DylinkerCommand&) = default;
DylinkerCommand::~DylinkerCommand(void) = default;

DylinkerCommand::DylinkerCommand(const dylinker_command *cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(cmd->cmd), cmd->cmdsize}
{}

const std::string& DylinkerCommand::name(void) const {
  return this->name_;
}

void DylinkerCommand::name(const std::string& name) {
  this->name_ = name;
}


void DylinkerCommand::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool DylinkerCommand::operator==(const DylinkerCommand& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool DylinkerCommand::operator!=(const DylinkerCommand& rhs) const {
  return not (*this == rhs);
}

std::ostream& DylinkerCommand::print(std::ostream& os) const {
  LoadCommand::print(os);
  os << std::hex;
  os << std::left
     << std::setw(35) << this->name();
  return os;
}

}
}
